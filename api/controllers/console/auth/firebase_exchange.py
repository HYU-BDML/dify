"""Firebase ID-token exchange endpoint (AUTH-01, Boram fork).

``POST /console/api/firebase-exchange`` is the sole intended console login path for
the Hanyang deployment. It takes a Firebase ID token, verifies it (see
``libs.firebase``), provisions/looks up the matching Dify account, joins it into the
single fixed workspace, and returns a console session via the standard auth cookies.

This controller is a near-clone of ``controllers.console.auth.oauth`` but never routes
through ``_generate_account`` / ``create_owner_tenant`` -- on a single-workspace fork
those raise. Instead it joins the fixed ``HANYANG_WORKSPACE_ID`` tenant directly so no
second workspace is ever created.
"""

import logging
from collections.abc import Callable
from functools import wraps

from flask import abort, make_response, request
from flask_restx import Resource
from pydantic import BaseModel, Field

from configs import dify_config
from controllers.common.fields import SimpleResultOptionalDataResponse
from controllers.common.schema import register_response_schema_models, register_schema_models
from controllers.console import console_ns
from controllers.console.wraps import setup_required
from extensions.ext_database import db
from libs import firebase
from libs.helper import extract_remote_ip
from libs.token import (
    set_access_token_to_cookie,
    set_csrf_token_to_cookie,
    set_refresh_token_to_cookie,
)
from models import Account, Tenant
from services.account_service import AccountService, TenantService

logger = logging.getLogger(__name__)


def firebase_exchange_enabled[**P, R](view: Callable[P, R]) -> Callable[P, R]:
    """Kill-switch: seal the Firebase exchange route unless FIREBASE_EXCHANGE_ENABLED.

    Mirrors the CONFIG-01 ``email_code_login_enabled`` gate, but keys off the
    ``dify_config`` flag (default ON) so the deployment can disable Firebase login
    without a code change.
    """

    @wraps(view)
    def decorated(*args: P.args, **kwargs: P.kwargs):
        if dify_config.FIREBASE_EXCHANGE_ENABLED:
            return view(*args, **kwargs)
        abort(403)

    return decorated


class FirebaseExchangePayload(BaseModel):
    id_token: str = Field(..., description="Firebase ID token obtained on the client")


register_schema_models(console_ns, FirebaseExchangePayload)
register_response_schema_models(console_ns, SimpleResultOptionalDataResponse)


def _firebase_provision(uid: str, email: str, name: str) -> Account:
    """Look up or create the account for a verified Firebase identity and join it
    into the fixed Hanyang workspace.

    Ordering matters: the fixed-workspace join happens *before* anything that could
    inspect the account's tenants, so no owner-tenant / second-workspace path can
    ever fire. Account creation uses ``create_account`` (account only) rather than
    ``create_account_and_tenant`` (which would spin up a personal workspace).
    """
    session = db.session()

    # 1) openid mapping first, then e-mail fallback.
    account: Account | None = Account.get_by_openid(firebase.FIREBASE_PROVIDER, uid)
    if not account:
        account = AccountService.get_user_through_email(email, session=session)

    # 2) create the account (no workspace) when it does not exist yet.
    if not account:
        account = AccountService.create_account(
            email=email,
            name=name,
            interface_language="ko-KR",
            is_setup=True,
            session=session,
        )

    # 3) join the single fixed workspace. Missing config / tenant => fail closed (500).
    workspace_id = dify_config.HANYANG_WORKSPACE_ID
    if not workspace_id:
        logger.error("HANYANG_WORKSPACE_ID is not configured; refusing Firebase exchange.")
        abort(500, "Firebase workspace is not configured.")

    tenant = session.get(Tenant, workspace_id)
    if tenant is None:
        logger.error("HANYANG_WORKSPACE_ID %s does not resolve to a tenant.", workspace_id)
        abort(500, "Firebase workspace not found.")

    # Idempotent: no-op if the account is already a member.
    TenantService.create_tenant_member(tenant, account, session=session, role="maker")

    # 4) persist the firebase uid -> account mapping (AccountIntegrate; no new column).
    AccountService.link_account_integrate(firebase.FIREBASE_PROVIDER, uid, account, session=session)

    return account


@console_ns.route("/firebase-exchange")
class FirebaseExchangeApi(Resource):
    """Exchange a Firebase ID token for a Dify console session."""

    @setup_required
    @firebase_exchange_enabled
    @console_ns.expect(console_ns.models[FirebaseExchangePayload.__name__])
    @console_ns.response(200, "Success", console_ns.models[SimpleResultOptionalDataResponse.__name__])
    @console_ns.response(401, "Firebase token rejected")
    def post(self):
        args = FirebaseExchangePayload.model_validate(console_ns.payload)

        try:
            uid, email = firebase.verify_and_extract(args.id_token)
        except firebase.FirebaseError as e:
            logger.warning("Firebase exchange rejected: %s", type(e).__name__)
            return {"error": "Firebase authentication failed."}, 401

        name = email.split("@", 1)[0]
        account = _firebase_provision(uid, email, name)

        token_pair = AccountService.login(
            account=account,
            session=db.session(),
            ip_address=extract_remote_ip(request),
        )

        # response-contract:ignore cookie-bearing Flask response
        response = make_response(
            SimpleResultOptionalDataResponse(result="success").model_dump(mode="json", exclude_none=True)
        )
        set_access_token_to_cookie(request, response, token_pair.access_token)
        set_refresh_token_to_cookie(request, response, token_pair.refresh_token)
        set_csrf_token_to_cookie(request, response, token_pair.csrf_token)

        return response
