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
from events.tenant_event import tenant_was_created
from models import Account, Tenant
from models.account import TenantAccountRole, TenantStatus
from services.enterprise.rbac_service import RBACService
from services.model_provider_service import ModelProviderService
from tasks.install_default_plugins_task import install_default_plugins_task

#: 학생 워크스페이스에 기본으로 매어 주는 LLM provider. `NEW_USER_DEFAULT_MODELS` 의
#: provider 부분과 **같은 값이어야** 한다 — 다르면 플러그인은 깔렸는데 자격증명이 다른
#: provider 에 붙어 모델이 안 잡힌다.
BORAM_DEFAULT_LLM_PROVIDER = "langgenius/anthropic/anthropic"
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
    # 이미 개인 워크스페이스가 있던 계정도 **거기로 착지**시킨다. 신규 생성 경로는
    # `_ensure_student_workspace` 안에서 이미 current 를 잡지만, 옛 공유 워크스페이스
    # 멤버십을 함께 가진 기존 계정은 이 한 줄이 없으면 그쪽으로 돌아간다. 멱등이라
    # 두 경로가 겹쳐도 무해하다.
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
            # 🔴 이미 있는 워크스페이스도 **모델이 있는지 확인**한다. 워크스페이스 생성과
            # 자격증명 심기는 별개 단계라, 앞선 배포에서 만들어졌거나 심기가 실패한 워크스페이스는
            # 모델 없이 남아 있다. 여기서 안 고치면 그 학생은 영영 빈 채로 쓴다 -- 프로비저너가
            # 「id 가 있으면 됐다」로 넘어가는 것과 같은 함정이다. 멱등이라 매번 불려도 무해하다.
            _ensure_model_ready(str(tenant.id))
            return tenant

    tenant = TenantService.create_tenant(
        name=f"{display_name}의 워크스페이스",
        is_setup=True,
        session=session,
    )
    TenantService.create_tenant_member(tenant, account, session=session, role=TenantAccountRole.OWNER)

    # RBAC 가 켜져 있으면 owner 역할을 실제로 매어 준다. `create_owner_tenant_if_not_exist`
    # 가 하는 것과 같은 처리다 -- 빠뜨리면 역할만 문자열로 남고 권한이 안 붙는다.
    if dify_config.RBAC_ENABLED:
        owner_role_id = AccountService._resolve_legacy_role_id(
            str(tenant.id), account.id, TenantAccountRole.OWNER
        )
        RBACService.MemberRoles.replace(
            tenant_id=str(tenant.id),
            account_id=account.id,
            member_account_id=account.id,
            role_ids=[owner_role_id],
            session=session,
        )

    account.set_current_tenant_with_session(tenant, session=session)
    session.commit()

    # 🔴 **이 이벤트를 빠뜨리면 새 워크스페이스가 빈 채로 시작한다.**
    # `tenant_was_created` -> `install_default_plugins_task` 가 신규 tenant 에
    # `NEW_USER_DEFAULT_PLUGIN_IDS`(모델 provider 는 1.x 부터 플러그인이다)를 깔고
    # `NEW_USER_DEFAULT_MODELS` 로 기본 모델을 잡는다. 저수준 `create_tenant()` 는 이 신호를
    # 안 보낸다 -- 보내는 쪽은 `create_owner_tenant_if_not_exist()` 다(2026-08-20 실측:
    # 이벤트 없이 만든 워크스페이스는 LLM provider 0 개였고 앱을 돌릴 수 없었다).
    tenant_was_created.send(tenant)

    # 🔴 **플러그인 설치를 기다린 뒤에 자격증명을 심는다.**
    # 위 이벤트의 핸들러는 `install_default_plugins_task.delay(...)` 로 **비동기** 큐잉을 한다.
    # 그래서 바로 자격증명을 심으려 들면 provider 가 아직 없어서
    # `ProviderNotFoundError: Provider langgenius/anthropic/anthropic does not exist.` 가 난다
    # (실측 2026-08-20 — 첫 구현이 정확히 이 경쟁 조건에 걸렸다).
    #
    # 워크스페이스 생성은 학생 **생애 1회**뿐이라 여기서 몇 초 기다리는 편이,
    # 「첫 로그인에는 모델이 없다」보다 낫다. 실패해도 던지지 않는다 — 아래 재시도가 받는다.
    _install_default_plugins_sync(str(tenant.id))
    _seed_model_credentials(str(tenant.id))

    logger.info("Created student workspace %s for account %s", tenant.id, account.id)
    return tenant


def _ensure_model_ready(tenant_id: str) -> None:
    """Seed the default model credential if this workspace still has none (idempotent).

    Cheap check first: if the workspace already has any configured LLM provider we do
    nothing, so the common path costs one query. Only a workspace that is still empty
    pays for the plugin install + credential write.
    """
    try:
        configured = ModelProviderService().get_provider_list(tenant_id=tenant_id, model_type="llm")
        if any(p.custom_configuration.current_credential_id for p in configured):
            return
    except Exception:
        logger.exception("Could not read provider list for workspace %s; attempting seed anyway", tenant_id)

    _install_default_plugins_sync(tenant_id)
    _seed_model_credentials(tenant_id)


def _install_default_plugins_sync(tenant_id: str) -> None:
    """Install the default plugins **in this request**, not on the worker queue.

    The `tenant_was_created` handler queues this with `.delay(...)`, which is the right
    default for Dify: tenant creation should not block on a marketplace download. But we
    need the model provider to exist *before* seeding its credential, and the seeding is
    the whole point of the M1-2 slice -- an async gap here means the student's first
    login lands in a workspace with no usable model.

    Calling the task function directly runs it inline (Celery tasks are plain callables).
    The queued copy still runs later and is idempotent, so the duplicate is harmless.
    """
    plugin_ids = dify_config.NEW_USER_DEFAULT_PLUGIN_ID_LIST
    if not plugin_ids:
        return
    try:
        install_default_plugins_task(tenant_id, plugin_ids)
    except Exception:
        logger.exception("Inline default-plugin install failed for workspace %s", tenant_id)


def _seed_model_credentials(tenant_id: str) -> None:
    """Give a brand-new student workspace a usable LLM (M1-2).

    🔴 **Why not the `HOSTED_ANTHROPIC_*` settings.** Those look like the obvious
    answer, and the roadmap originally called for them, but ``HostingConfiguration``
    bails out on the first line unless the deployment is the *cloud* edition::

        def init_app(self, app):
            if dify_config.DEPLOYMENT_EDITION != DeploymentEdition.CLOUD:
                return

    We are self-hosted, so every ``HOSTED_*`` value is read and then ignored
    (measured 2026-08-20: env set, provider list still empty). Seeding a real
    per-tenant credential is the path that actually works here.

    The plugin itself arrives via ``tenant_was_created`` ->
    ``install_default_plugins_task``; a provider only becomes *usable* once a
    credential exists, so this runs after that signal.

    Failure is logged, not raised: the workspace and the console session are still
    valid without a model, and killing the login over a seeding hiccup would lock the
    student out of a workspace that otherwise works. The console shows an unconfigured
    provider in that case, which is a state a person can see and fix.
    """
    api_key = dify_config.BORAM_ANTHROPIC_API_KEY
    if not api_key:
        logger.warning("BORAM_ANTHROPIC_API_KEY is unset; workspace %s starts without a model.", tenant_id)
        return

    try:
        ModelProviderService().create_provider_credential(
            tenant_id=tenant_id,
            provider=BORAM_DEFAULT_LLM_PROVIDER,
            credentials={"anthropic_api_key": api_key},
            credential_name="boram-default",
        )
        logger.info("Seeded %s credential for workspace %s", BORAM_DEFAULT_LLM_PROVIDER, tenant_id)
    except Exception:
        logger.exception("Failed to seed model credential for workspace %s", tenant_id)
        return

    _apply_default_models(tenant_id)


def _apply_default_models(tenant_id: str) -> None:
    """Pin the workspace's default model **after** the credential exists.

    `install_default_plugins_task` already tries this, but it runs before the
    credential is in place (it is the thing that installs the plugin), so the call
    fails there and the workspace ends up with *no* default pinned. Dify then answers
    "default model" queries with whatever the provider lists first -- which is not the
    model we configured (measured 2026-08-20: NEW_USER_DEFAULT_MODELS said
    claude-sonnet-5, the workspace reported claude-opus-5).

    Reading the same `NEW_USER_DEFAULT_MODELS` setting keeps one source of truth: the
    deploy env decides the model, this only makes it stick.
    """
    service = ModelProviderService()
    for model_type, provider, model in dify_config.NEW_USER_DEFAULT_MODEL_LIST:
        try:
            service.update_default_model_of_model_type(
                tenant_id=tenant_id,
                model_type=model_type,
                provider=provider,
                model=model,
            )
            logger.info("Pinned default %s=%s for workspace %s", model_type, model, tenant_id)
        except Exception:
            logger.exception(
                "Failed to pin default model for workspace %s (%s/%s)", tenant_id, provider, model
            )


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
