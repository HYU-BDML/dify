"""Boram app-provisioning console endpoint (PROV-01, Boram fork).

``POST /console/api/boram/provision-app`` lets the Boram backend create a Dify app
(optionally from a DSL YAML) and mint an app-scoped Service-API token in a single call.

Every console app-creation / token-issuance route is gated by ``@login_required``
(an Account JWT), which the Boram machine backend does not hold. Rather than forge a
session, this endpoint follows the AUTH-01 ``firebase_exchange`` pattern: a shared
service secret (``X-Boram-Service-Secret``) is the authenticator, so no login is
required.

The underlying services (``AppService.create_app`` / ``AppDslService.import_app``)
still need an ``Account`` for authorship (``created_by`` / ``maintainer``) and, more
importantly, for ``account.current_tenant_id`` — the tenant the app is created in.
The target workspace is the caller-supplied ``tenant_id`` (the student's own
workspace), falling back to ``HANYANG_WORKSPACE_ID`` for legacy single-workspace
callers. Since there is no logged-in user, that workspace's *owner* account is loaded
and its current-tenant is attached in-session via ``Account.set_tenant_id_with_session``
(the same "manipulate a tenant without a live session" seam the Firebase provisioner uses).

Idempotency: this endpoint is intentionally NON-idempotent — every call creates a
fresh app. The Boram side guards against duplicates (``dify_app_id IS NULL``) before
ever calling here, so no dedup is attempted server-side.
"""

import hmac
import logging
from collections.abc import Callable
from functools import wraps
from typing import Literal

from flask import abort, request
from flask_restx import Resource
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from configs import dify_config
from controllers.common.schema import register_response_schema_models, register_schema_models
from controllers.console import console_ns
from controllers.console.wraps import setup_required
from extensions.ext_database import db
from fields.base import ResponseModel
from libs.helper import dump_response
from models import Account, App, Tenant, TenantAccountJoin, TenantAccountRole
from models.enums import ApiTokenType
from models.model import ApiToken
from services.app_dsl_service import AppDslService
from services.app_service import AppService, CreateAppParams
from services.entities.dsl_entities import ImportMode, ImportStatus

logger = logging.getLogger(__name__)


def boram_service_secret_required[**P, R](view: Callable[P, R]) -> Callable[P, R]:
    """Authenticate the Boram provisioning route with the shared service secret.

    Mirrors the AUTH-01 ``firebase_exchange_enabled`` kill-switch decorator, but also
    performs the actual authentication: it fails closed with ``403`` when the
    provisioning kill-switch is off, when ``BORAM_SERVICE_SECRET`` is unset, or when the
    ``X-Boram-Service-Secret`` header does not match it (compared in constant time).
    """

    @wraps(view)
    def decorated(*args: P.args, **kwargs: P.kwargs):
        if not dify_config.BORAM_PROVISION_ENABLED:
            abort(403)

        expected = dify_config.BORAM_SERVICE_SECRET
        if not expected:
            abort(403)

        provided = request.headers.get("X-Boram-Service-Secret", "")
        if not hmac.compare_digest(provided, expected):
            abort(403)

        return view(*args, **kwargs)

    return decorated


class ProvisionAppPayload(BaseModel):
    name: str = Field(..., min_length=1, description="App name")
    mode: Literal["chat", "agent-chat", "advanced-chat", "workflow", "completion"] = Field(
        ..., description="App mode (ignored when dsl_yaml is supplied — the DSL decides the mode)"
    )
    dsl_yaml: str | None = Field(
        default=None,
        description="When present, the app is imported from this DSL YAML instead of created blank.",
    )
    agent_ref: str | None = Field(
        default=None,
        description="Reserved Boram-side reference for the source agent; recorded by the caller, not consumed here.",
    )
    tenant_id: str | None = Field(
        default=None,
        description="Target Dify workspace (the student's own tenant) to create the app in. "
        "Falls back to HANYANG_WORKSPACE_ID when omitted (legacy single-workspace callers).",
    )


class ProvisionAppResponse(ResponseModel):
    result: str
    dify_app_id: str
    dify_app_mode: str
    app_token: str
    enable_api: bool


register_schema_models(console_ns, ProvisionAppPayload)
register_response_schema_models(console_ns, ProvisionAppResponse)


def _resolve_workspace_owner(workspace_id: str, *, session: Session) -> Account:
    """Load the owner ``Account`` of the fixed workspace and attach that tenant to it.

    The owner is used purely as the authorship/tenant context for the created app; no
    login happens. ``set_tenant_id_with_session`` populates ``current_tenant_id`` (and
    the privileged owner role) that ``create_app`` / ``import_app`` read.
    """
    join = session.scalar(
        select(TenantAccountJoin)
        .where(
            TenantAccountJoin.tenant_id == workspace_id,
            TenantAccountJoin.role == TenantAccountRole.OWNER,
        )
        .limit(1)
    )
    if join is None:
        logger.error("Boram workspace %s has no owner account; refusing provisioning.", workspace_id)
        abort(500, "Boram workspace has no owner.")

    account = session.get(Account, join.account_id)
    if account is None:
        logger.error("Boram workspace owner account %s not found.", join.account_id)
        abort(500, "Boram workspace owner account not found.")

    account.set_tenant_id_with_session(workspace_id, session=session)
    return account


@console_ns.route("/boram/provision-app")
class BoramProvisionAppApi(Resource):
    """Create a Dify app + Service-API token for the Boram backend (secret-authenticated)."""

    @setup_required
    @boram_service_secret_required
    @console_ns.expect(console_ns.models[ProvisionAppPayload.__name__])
    @console_ns.response(200, "Success", console_ns.models[ProvisionAppResponse.__name__])
    @console_ns.response(403, "Service secret rejected or endpoint disabled")
    def post(self):
        args = ProvisionAppPayload.model_validate(console_ns.payload)

        # Target the caller-supplied student tenant; fall back to the legacy fixed
        # workspace. Unset both fails closed (500) rather than leaking into a
        # default/unexpected tenant.
        workspace_id = args.tenant_id or dify_config.HANYANG_WORKSPACE_ID
        if not workspace_id:
            logger.error("No tenant_id supplied and HANYANG_WORKSPACE_ID unset; refusing Boram provisioning.")
            abort(500, "Boram target workspace is not configured.")

        with Session(db.engine, expire_on_commit=False) as session:
            tenant = session.get(Tenant, workspace_id)
            if tenant is None:
                logger.error("HANYANG_WORKSPACE_ID %s does not resolve to a tenant.", workspace_id)
                abort(500, "Boram workspace not found.")

            account = _resolve_workspace_owner(workspace_id, session=session)

            # (1) Create the app: from DSL when provided, otherwise a blank app of `mode`.
            if args.dsl_yaml:
                import_service = AppDslService(session)
                result = import_service.import_app(
                    account=account,
                    import_mode=ImportMode.YAML_CONTENT,
                    yaml_content=args.dsl_yaml,
                    name=args.name,
                )
                if result.status == ImportStatus.FAILED:
                    session.rollback()
                    logger.error("Boram provisioning DSL import failed: %s", result.error)
                    abort(400, f"DSL import failed: {result.error}")
                if result.status == ImportStatus.PENDING:
                    # Version-mismatch confirmation flow is interactive; unsupported here.
                    session.rollback()
                    abort(400, "DSL import requires confirmation (version mismatch); unsupported.")
                app = session.get(App, result.app_id)
                if app is None:
                    session.rollback()
                    logger.error("Boram provisioning: imported app %s vanished.", result.app_id)
                    abort(500, "Imported app not found.")
            else:
                params = CreateAppParams(name=args.name, mode=args.mode)
                app = AppService().create_app(workspace_id, params, account, session=session)

            # (2) Guarantee the Service API is enabled — validate_app_token 403s otherwise.
            app.enable_api = True

            # (3) Mint an app-scoped Service-API token (type='app', prefix 'app-').
            token_value = ApiToken.generate_api_key("app-", 24, session=session)
            api_token = ApiToken()
            api_token.app_id = app.id
            api_token.tenant_id = workspace_id
            api_token.token = token_value
            api_token.type = ApiTokenType.APP
            session.add(api_token)

            session.commit()

            return dump_response(
                ProvisionAppResponse,
                {
                    "result": "success",
                    "dify_app_id": str(app.id),
                    "dify_app_mode": str(app.mode),
                    "app_token": token_value,
                    "enable_api": app.enable_api,
                },
            )
