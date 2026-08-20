"""Boram console-session handoff (AUTH-02, Boram fork).

Two endpoints that let the Boram BFF (rita.ai.kr) open the Dify console for an
already-authenticated Boram user without any client-side Firebase session:

1. ``POST /console/api/boram/console-session`` -- server-to-server. Authenticated by
   the ``X-Boram-Service-Secret`` header (constant-time compare). Takes ``{uid,
   email?, name?}``, provisions/looks up the account exactly like the Firebase
   exchange (openid mapping -> e-mail fallback -> create, then idempotent join into
   the fixed workspace as ``maker``), and returns a **single-use, short-lived code**.
   No cookies are set here -- a server-to-server response cannot reach the browser.

2. ``GET /console/api/boram/session-redeem?code=...&redirect_url=...`` -- loaded by
   the browser (iframe). Consumes the code atomically (Redis ``GETDEL``), logs the
   account in via the standard ``AccountService.login``, sets the standard auth
   cookies as a first-party response on this origin, and 302-redirects to
   ``redirect_url`` (same-origin relative paths only).

Why not reuse ``firebase-exchange``: that endpoint requires a *client-side* Firebase
ID token, but Boram deliberately destroys the client SDK session right after login
(httpOnly-cookie-only design), and its domain gate (``hanyang.ac.kr``) excludes
phone-OTP and general e-mail users. Here the Boram BFF is the authenticator: it has
already verified its own ``__session`` cookie before calling endpoint 1. This is the
"1회용 code redirect" variant recommended in ``docs/dify-fork-patches.md`` (AUTH-01
design notes).

Security posture (ADR: service-secret authority expansion):
- The secret gains "mint a session for uid X" authority, so the endpoint prefers a
  **dedicated** ``BORAM_SESSION_SECRET`` and only falls back to
  ``BORAM_SERVICE_SECRET`` when the dedicated one is unset -- deployments can rotate
  or restrict the session credential independently.
- Codes are 256-bit, single-use (``GETDEL``), and expire after 60 seconds.
- Every issuance is logged with account id for audit.
- ``BORAM_SESSION_HANDOFF_ENABLED`` is a kill-switch mirroring
  ``FIREBASE_EXCHANGE_ENABLED``.
"""

import hmac
import logging
import secrets
from collections.abc import Callable
from functools import wraps

from flask import abort, redirect, request
from flask_restx import Resource
from pydantic import BaseModel, Field

from configs import dify_config
from controllers.common.schema import register_schema_models
from controllers.console import console_ns
from controllers.console.wraps import setup_required
from extensions.ext_database import db
from extensions.ext_redis import redis_client
from libs import firebase
from libs.helper import extract_remote_ip
from libs.token import (
    set_access_token_to_cookie,
    set_csrf_token_to_cookie,
    set_refresh_token_to_cookie,
)
from models import Account, Tenant
from models.account import TenantAccountRole, TenantStatus
from services.account_service import AccountService, TenantService

logger = logging.getLogger(__name__)

#: Redis key prefix for issued handoff codes. Value is the account id.
_CODE_KEY_PREFIX = "boram:console_code:"
#: Handoff codes live this long (seconds). Long enough for one iframe navigation.
_CODE_TTL_SECONDS = 60


def _session_secret() -> str | None:
    """The credential that authorizes session minting.

    Prefers the dedicated ``BORAM_SESSION_SECRET`` so it can be rotated separately
    from the provisioning secret; falls back to ``BORAM_SERVICE_SECRET``.
    """
    return dify_config.BORAM_SESSION_SECRET or dify_config.BORAM_SERVICE_SECRET


def boram_session_enabled[**P, R](view: Callable[P, R]) -> Callable[P, R]:
    """Kill-switch mirroring ``firebase_exchange_enabled`` (AUTH-01)."""

    @wraps(view)
    def decorated(*args: P.args, **kwargs: P.kwargs):
        if dify_config.BORAM_SESSION_HANDOFF_ENABLED:
            return view(*args, **kwargs)
        abort(403)

    return decorated


class BoramConsoleSessionPayload(BaseModel):
    uid: str = Field(..., min_length=1, description="Boram user id (Firebase UID, text PK)")
    email: str | None = Field(None, description="Verified account e-mail when the user has one")
    name: str | None = Field(None, description="Display name for first-time provisioning")


register_schema_models(console_ns, BoramConsoleSessionPayload)


def _provision(uid: str, email: str | None, name: str | None) -> Account:
    """Look up or create the account for a BFF-asserted identity and join it into
    the fixed workspace.

    Near-clone of ``firebase_exchange._firebase_provision`` minus the Firebase token
    verification (the BFF already authenticated the user). Phone-OTP users have no
    e-mail, so a stable synthetic address keyed by uid keeps ``Account.email``
    unique without colliding with any real mailbox.
    """
    session = db.session()

    effective_email = email or f"{uid}@uid.rita.ai.kr"
    effective_name = name or effective_email.split("@", 1)[0]

    account: Account | None = Account.get_by_openid(firebase.FIREBASE_PROVIDER, uid)
    if not account:
        account = AccountService.get_user_through_email(effective_email, session=session)

    if not account:
        account = AccountService.create_account(
            email=effective_email,
            name=effective_name,
            interface_language="ko-KR",
            is_setup=True,
            session=session,
        )

    tenant = _ensure_student_workspace(session, account, effective_name)
    TenantService.switch_tenant(account, tenant.id, session=session)
    AccountService.link_account_integrate(firebase.FIREBASE_PROVIDER, uid, account, session=session)

    return account


def _ensure_student_workspace(session, account: Account, display_name: str) -> Tenant:
    """Return the student's **own** workspace, creating it on first use (M1-1).

    Why this exists -- every student used to land in one shared workspace
    (``HANYANG_WORKSPACE_ID``) as a ``maker``. That was the 2026-08-13 "single
    workspace" posture; the 2026-08-14 written permission widened the licence to one
    workspace per student, and the 2026-08-16 Dify-native plan depends on it.

    What the sharing actually leaked (measured 2026-08-20 against production): apps
    and datasets were **not** visible across accounts -- the ``maker`` role already
    scopes those to their creator (a second account got 404 on an app and 403 on a
    dataset). What *was* shared is workspace-level: tool provider credentials (a key
    one student configures becomes usable by every other app in the workspace), model
    settings, and the member list (every student saw every other student's name and
    e-mail). Per-student workspaces close all three.

    Idempotency: the student's workspace is found by "a tenant this account owns".
    No mapping column is stored -- ownership *is* the mapping, so it cannot drift out
    of sync with the join table.

    ``is_setup=True`` bypasses ``is_workspace_creation_allowed()`` **on purpose**:
    this is a server-controlled provision for an already-authenticated identity, not
    a user-initiated "create workspace" action. The console API exposes no workspace
    creation endpoint at all (``POST /console/api/workspaces`` answers 405), so this
    stays the only path -- students still cannot mint workspaces for themselves.

    🔴 Existing accounts keep their old membership in the shared workspace; this only
    changes where they *land*. Cleaning up those stale joins is a separate migration
    (roadmap M1-5) -- doing it here would delete data on a read-shaped request.
    """
    for ta, tenant in TenantService.get_account_memberships(account.id, session=session):
        if ta.role == TenantAccountRole.OWNER and tenant.status == TenantStatus.NORMAL:
            return tenant

    tenant = TenantService.create_tenant(
        name=f"{display_name}의 워크스페이스",
        is_setup=True,
        session=session,
    )
    TenantService.create_tenant_member(tenant, account, session=session, role=TenantAccountRole.OWNER)
    logger.info("Created student workspace %s for account %s", tenant.id, account.id)
    return tenant


@console_ns.route("/boram/console-session")
class BoramConsoleSessionApi(Resource):
    """Issue a single-use console-session code for a BFF-asserted user."""

    @setup_required
    @boram_session_enabled
    @console_ns.expect(console_ns.models[BoramConsoleSessionPayload.__name__])
    @console_ns.response(200, "Code issued")
    @console_ns.response(401, "Service secret missing or wrong")
    def post(self):
        secret = _session_secret()
        provided = request.headers.get("X-Boram-Service-Secret", "")
        if not secret or not provided or not hmac.compare_digest(secret, provided):
            return {"error": "Service authentication failed."}, 401

        args = BoramConsoleSessionPayload.model_validate(console_ns.payload)
        account = _provision(args.uid, args.email, args.name)

        code = secrets.token_urlsafe(32)
        redis_client.setex(f"{_CODE_KEY_PREFIX}{code}", _CODE_TTL_SECONDS, account.id)
        # Audit trail: who was issued a console session, and from where.
        logger.info(
            "boram console-session issued: account=%s uid=%s ip=%s",
            account.id,
            args.uid,
            extract_remote_ip(request),
        )

        return {"code": code, "expires_in": _CODE_TTL_SECONDS}


@console_ns.route("/boram/session-redeem")
class BoramSessionRedeemApi(Resource):
    """Consume a handoff code: set auth cookies first-party and redirect into the console."""

    @setup_required
    @boram_session_enabled
    @console_ns.response(302, "Cookies set, redirecting into the console")
    @console_ns.response(401, "Code missing, expired, or already used")
    def get(self):
        code = request.args.get("code", "")
        if not code:
            return {"error": "Missing code."}, 401

        # Atomic single-use consumption -- a replayed URL finds nothing.
        account_id = redis_client.getdel(f"{_CODE_KEY_PREFIX}{code}")
        if not account_id:
            return {"error": "Code expired or already used."}, 401
        if isinstance(account_id, bytes):
            account_id = account_id.decode("utf-8")

        account = db.session().get(Account, account_id)
        if account is None:
            logger.error("boram session-redeem: account %s vanished after code issue.", account_id)
            return {"error": "Account not found."}, 401

        # Same-origin relative paths only: must start with exactly one '/'.
        # ('//host' is a protocol-relative absolute URL -- an open-redirect vector.)
        redirect_url = request.args.get("redirect_url", "/apps")
        if not redirect_url.startswith("/") or redirect_url.startswith("//"):
            redirect_url = "/apps"

        token_pair = AccountService.login(
            account=account,
            session=db.session(),
            ip_address=extract_remote_ip(request),
        )

        # response-contract:ignore cookie-bearing Flask redirect response
        response = redirect(redirect_url, code=302)
        set_access_token_to_cookie(request, response, token_pair.access_token)
        set_refresh_token_to_cookie(request, response, token_pair.refresh_token)
        set_csrf_token_to_cookie(request, response, token_pair.csrf_token)

        return response
