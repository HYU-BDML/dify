"""Controller decorators for console app resources.

`get_app_model` still supports legacy handlers backed by Flask-SQLAlchemy's
scoped session. Trial app handlers compose `get_app_model_with_trial` under
`controllers.common.session.with_session` and always reuse that request session.
"""

from collections.abc import Callable
from functools import wraps
from typing import cast, overload

from sqlalchemy import select
from sqlalchemy.orm import Session

from configs import dify_config
from controllers.common.session import with_session
from controllers.common.wraps import RBACPermission, RBACResourceScope, enforce_rbac_access
from controllers.console.app.error import AppNotFoundError
from extensions.ext_database import db
from libs.login import current_account_with_tenant
from models import App, AppMode, TrialApp
from models.account import TenantAccountRole
from models.agent import AgentScope
from services.recommended_app_service import RecommendedAppService

__all__ = [
    "agent_manage_required_for_agent_app",
    "get_app_model",
    "get_app_model_with_trial",
    "with_session",
]


def _owner_scope_conditions(app_id: str, owner_only: bool):
    """App by-id 조회의 소유권 격리 조건을 만든다 (OWN-01, 정오 결정 2026-08-14).

    소유권 축은 `maintainer`(양도 가능 — 멤버 제거 시 owner 로 이전, account_service.py:1776-1783)이고
    `created_by` 는 불변 작성자 기록으로 남긴다. 정책:
    - read (owner_only=False): 소유자 또는 privileged(owner/admin) — 관리자는 운영 지원차 조회 가능
    - mutation (owner_only=True): 소유자만 — 관리자도 남의 App 을 수정·삭제·게시할 수 없다
    소유권 불일치는 owner 절이 안 맞아 None → AppNotFoundError(404)로 존재를 숨긴다.
    """
    user, current_tenant_id = current_account_with_tenant()
    conds = [App.id == app_id, App.tenant_id == current_tenant_id, App.status == "normal"]
    if owner_only or not TenantAccountRole.is_privileged_role(user.current_role):
        conds.append(App.maintainer == user.id)
    return conds


def _load_app_model(session: Session, app_id: str, owner_only: bool = False) -> App | None:
    """Load the tenant-scoped app row with the request session owned by `with_session`."""
    app_model = session.scalar(select(App).where(*_owner_scope_conditions(app_id, owner_only)).limit(1))
    return app_model


def _load_app_model_from_scoped_session(app_id: str, owner_only: bool = False) -> App | None:
    """Load the app row for legacy handlers that have not adopted request session injection yet."""
    app_model = db.session.scalar(select(App).where(*_owner_scope_conditions(app_id, owner_only)).limit(1))
    return app_model


def _load_app_model_with_trial(session: Session, app_id: str) -> App | None:
    """Load a normal app through its trial registration without applying current-tenant scope."""
    app_model = session.scalar(
        select(App).join(TrialApp, TrialApp.app_id == App.id).where(App.id == app_id, App.status == "normal").limit(1)
    )
    return app_model


def agent_manage_required_for_agent_app[**P, R](view: Callable[P, R]) -> Callable[P, R]:
    """Gate generic app management routes that target an Agent App.

    A hidden workflow-only backing App only reuses the App runtime and is not
    part of the general app management plane, so generic routes reject it
    outright. Managing a roster Agent App mutates the roster Agent behind it
    (rename/icon sync, archive, API enablement), so it additionally requires
    workspace ``agent.manage`` on top of the route's existing App permission
    checks when RBAC is enabled. A no-op for non-agent Apps. Must be placed
    above ``get_app_model`` so the ``app_id`` path parameter is still present.
    """

    @wraps(view)
    def decorated(*args: P.args, **kwargs: P.kwargs) -> R:
        raw_app_id = kwargs.get("app_id") or kwargs.get("resource_id")
        if raw_app_id is not None:
            app_model = _load_app_model_from_scoped_session(str(raw_app_id))
            binding = (
                app_model.agent_app_binding_with_session(session=db.session(), include_archived=True)
                if app_model is not None
                else None
            )
            if binding is not None:
                if binding.scope == AgentScope.WORKFLOW_ONLY:
                    raise AppNotFoundError()
                if dify_config.RBAC_ENABLED:
                    current_user, current_tenant_id = current_account_with_tenant()
                    enforce_rbac_access(
                        tenant_id=current_tenant_id,
                        account_id=current_user.id,
                        resource_type=RBACResourceScope.WORKSPACE,
                        scene=RBACPermission.AGENT_MANAGE,
                        resource_required=False,
                    )
        return view(*args, **kwargs)

    return decorated


def _get_injected_session(args: tuple[object, ...]) -> Session | None:
    """Return the request session inserted by `with_session`, if this handler has been migrated."""
    if len(args) < 2:
        return None

    candidate = args[1]
    if isinstance(candidate, Session):
        return candidate

    if hasattr(candidate, "scalar") and hasattr(candidate, "commit") and hasattr(candidate, "rollback"):
        return cast(Session, candidate)

    return None


@overload
def get_app_model[**P, R](
    view: Callable[P, R],
    *,
    mode: AppMode | list[AppMode] | None = None,
    owner_only: bool = False,
) -> Callable[P, R]: ...


@overload
def get_app_model[**P, R](
    view: None = None,
    *,
    mode: AppMode | list[AppMode] | None = None,
    owner_only: bool = False,
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


def get_app_model[**P, R](
    view: Callable[P, R] | None = None,
    *,
    mode: AppMode | list[AppMode] | None = None,
    owner_only: bool = False,
) -> Callable[P, R] | Callable[[Callable[P, R]], Callable[P, R]]:
    """Inject the App model for handlers that receive an `app_id` path parameter.

    New handlers may compose `@with_session` above this decorator so the app row
    is loaded through the same request-scoped session used by the controller.
    Existing handlers continue to work through `db.session` until migrated.

    ``owner_only=True`` (mutation 라우트: 수정·삭제·게시·API key·draft 저장)는 소유자
    (`maintainer`)만 통과시킨다 — 관리자도 남의 App 을 변경할 수 없다. 기본(read)은
    관리자에게 조회를 허용한다. OWN-01, 정오 결정 2026-08-14.
    """

    def decorator(view_func: Callable[P, R]) -> Callable[P, R]:
        @wraps(view_func)
        def decorated_view(*args: P.args, **kwargs: P.kwargs) -> R:
            if not kwargs.get("app_id"):
                raise ValueError("missing app_id in path parameters")

            app_id = kwargs.get("app_id")
            app_id = str(app_id)

            del kwargs["app_id"]

            session = _get_injected_session(args)
            if session is None:
                app_model = _load_app_model_from_scoped_session(app_id, owner_only)
            else:
                app_model = _load_app_model(session, app_id, owner_only)

            if not app_model:
                raise AppNotFoundError()

            app_mode = AppMode.value_of(app_model.mode)

            if mode is not None:
                if isinstance(mode, list):
                    modes = mode
                else:
                    modes = [mode]

                if app_mode not in modes:
                    mode_values = {m.value for m in modes}
                    raise AppNotFoundError(f"App mode is not in the supported list: {mode_values}")

            kwargs["app_model"] = app_model

            return view_func(*args, **kwargs)

        return decorated_view

    if view is None:
        return decorator
    else:
        return decorator(view)


@overload
def get_app_model_with_trial[**P, R](
    view: Callable[P, R],
    *,
    mode: AppMode | list[AppMode] | None = None,
) -> Callable[P, R]: ...


@overload
def get_app_model_with_trial[**P, R](
    view: None = None,
    *,
    mode: AppMode | list[AppMode] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


def get_app_model_with_trial[**P, R](
    view: Callable[P, R] | None = None,
    *,
    mode: AppMode | list[AppMode] | None = None,
) -> Callable[P, R] | Callable[[Callable[P, R]], Callable[P, R]]:
    """Inject a trial-registered or recommended App using the Session supplied by `with_session`."""

    def decorator(view_func: Callable[P, R]) -> Callable[P, R]:
        @wraps(view_func)
        def decorated_view(*args: P.args, **kwargs: P.kwargs) -> R:
            if not kwargs.get("app_id"):
                raise ValueError("missing app_id in path parameters")

            app_id = kwargs.get("app_id")
            app_id = str(app_id)

            del kwargs["app_id"]

            session = _get_injected_session(args)
            if session is None:
                raise RuntimeError("get_app_model_with_trial requires @with_session")
            app_model = _load_app_model_with_trial(session, app_id)
            if app_model is None:
                app_model = RecommendedAppService.get_app(app_id, session=session)

            if not app_model:
                raise AppNotFoundError()

            app_mode = AppMode.value_of(app_model.mode)

            if mode is not None:
                if isinstance(mode, list):
                    modes = mode
                else:
                    modes = [mode]

                if app_mode not in modes:
                    mode_values = {m.value for m in modes}
                    raise AppNotFoundError(f"App mode is not in the supported list: {mode_values}")

            kwargs["app_model"] = app_model

            return view_func(*args, **kwargs)

        return decorated_view

    if view is None:
        return decorator
    else:
        return decorator(view)
