"""Boram app-copy console endpoint (COPY-01, Boram fork).

``POST /console/api/boram/copy-app`` lets the Boram backend **clone an already
published Dify app into a target (student) workspace** and mint an app-scoped
Service-API token in a single call. It is the sibling of PROV-01
(``boram_provision.py``): where provision creates a *blank* (or DSL) app, copy
*exports the source app's native DSL and re-imports it* into the target tenant, so
an adopted ("fork") agent inherits the original's behaviour, not just an empty shell.

Auth, tenant resolution and token issuance are shared with PROV-01 verbatim:

* Authentication is the same shared service secret (``X-Boram-Service-Secret``) —
  the ``boram_service_secret_required`` decorator is imported, not re-implemented.
* The target workspace's *owner* account supplies the authorship / ``current_tenant_id``
  context that ``AppDslService.import_app`` reads — resolved via the shared
  ``_resolve_workspace_owner`` seam (no live login).
* The Service-API is force-enabled and an ``app-`` scoped ``ApiToken`` is minted with
  the exact pattern PROV-01 uses.

## Source → target is cross-tenant, so secrets are NOT exported
The source app lives in the author's workspace; its DSL secrets are encrypted with
*that* tenant's key and are both meaningless and a leak if carried into the student's
tenant. Export therefore uses ``include_secret=False`` — the same shareable-export
choice ``controllers/console/app/app.py`` makes for its public export path. The
student re-supplies their own provider credentials, exactly as a Marketplace adopt
implies.

## Idempotency
Like PROV-01 this endpoint is intentionally NON-idempotent — every call clones a
fresh app. The Boram side (``lib/dify-bridge/copy.ts``) serializes adoption under a
``FOR UPDATE`` lock and re-checks ``dify_app_id IS NULL`` before ever calling here,
so no server-side dedup is attempted. A missing source or a failed export/import
returns a non-2xx, which the Boram caller folds into its blank-provision fallback.
"""

import logging
from typing import Any

from flask import abort
from flask_restx import Resource
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from configs import dify_config
from controllers.common.schema import register_response_schema_models, register_schema_models
from controllers.console import console_ns

# Reuse PROV-01's auth decorator and workspace-owner seam verbatim — copy shares the
# exact same "manipulate a tenant without a live session" contract as provision.
from controllers.console.boram_provision import (
    _resolve_workspace_owner,
    boram_service_secret_required,
)
from controllers.console.wraps import setup_required
from extensions.ext_database import db
from fields.base import ResponseModel
from libs.helper import dump_response
from models import App, Tenant
from models.enums import ApiTokenType
from models.model import ApiToken
from services.app_dsl_service import AppDslService
from services.entities.dsl_entities import ImportMode, ImportStatus

logger = logging.getLogger(__name__)


class CopyAppPayload(BaseModel):
    source_app_id: str = Field(..., min_length=1, description="Id of the published Dify app to clone.")
    target_tenant_id: str | None = Field(
        default=None,
        description="Target Dify workspace (the student's own tenant) to clone the app into. "
        "Falls back to HANYANG_WORKSPACE_ID when omitted (legacy single-workspace callers).",
    )
    name: str | None = Field(
        default=None,
        min_length=1,
        description="Name for the cloned app. When omitted, the source app's own name (from its DSL) is kept.",
    )
    agent_ref: str | None = Field(
        default=None,
        description="Reserved Boram-side reference for the source agent; recorded by the caller, not consumed here.",
    )


class CopyAppResponse(ResponseModel):
    result: str
    dify_app_id: str
    dify_app_mode: str
    app_token: str
    enable_api: bool


register_schema_models(console_ns, CopyAppPayload)
register_response_schema_models(console_ns, CopyAppResponse)


@console_ns.route("/boram/copy-app")
class BoramCopyAppApi(Resource):
    """Clone a published Dify app into a target workspace + mint a Service-API token."""

    @setup_required
    @boram_service_secret_required
    @console_ns.expect(console_ns.models[CopyAppPayload.__name__])
    @console_ns.response(200, "Success", console_ns.models[CopyAppResponse.__name__])
    @console_ns.response(403, "Service secret rejected or endpoint disabled")
    @console_ns.response(404, "Source app not found")
    def post(self):
        args = CopyAppPayload.model_validate(console_ns.payload)

        # Target the caller-supplied student tenant; fall back to the legacy fixed
        # workspace. Unset both fails closed (500) rather than leaking into a
        # default/unexpected tenant (identical guard to PROV-01).
        workspace_id = args.target_tenant_id or dify_config.HANYANG_WORKSPACE_ID
        if not workspace_id:
            logger.error("No target_tenant_id supplied and HANYANG_WORKSPACE_ID unset; refusing Boram copy.")
            abort(500, "Boram target workspace is not configured.")

        with Session(db.engine, expire_on_commit=False) as session:
            tenant = session.get(Tenant, workspace_id)
            if tenant is None:
                logger.error("Boram copy target workspace %s does not resolve to a tenant.", workspace_id)
                abort(500, "Boram workspace not found.")

            # (1) Load the source app by id. It may live in a *different* tenant than the
            # target (marketplace adopt across workspaces), so it is looked up by primary
            # key without a tenant filter — this route is service-secret authenticated.
            source_app = session.get(App, args.source_app_id)
            if source_app is None:
                logger.warning("Boram copy source app %s not found.", args.source_app_id)
                abort(404, "Source app not found.")

            # (2) Export the source app's native DSL. include_secret=False: the source's
            # secrets are encrypted with its own tenant key and must not cross tenants
            # (see module docstring) — mirrors the shareable-export path in app.py.
            try:
                dsl_yaml = AppDslService.export_dsl(
                    app_model=source_app,
                    session=session,
                    include_secret=False,
                )
            except Exception as e:
                session.rollback()
                logger.exception("Boram copy: DSL export of source app %s failed.", args.source_app_id)
                abort(400, f"DSL export failed: {e}")

            # (3) Resolve the target workspace owner as the authorship / tenant context and
            # import the DSL as a brand-new app in that tenant (no app_id → fresh clone).
            account = _resolve_workspace_owner(workspace_id, session=session)

            import_service = AppDslService(session)
            result = import_service.import_app(
                account=account,
                import_mode=ImportMode.YAML_CONTENT,
                yaml_content=dsl_yaml,
                name=args.name,
            )
            if result.status == ImportStatus.FAILED:
                session.rollback()
                logger.error("Boram copy DSL import failed: %s", result.error)
                abort(400, f"DSL import failed: {result.error}")
            if result.status == ImportStatus.PENDING:
                # Version-mismatch confirmation flow is interactive; unsupported here.
                session.rollback()
                abort(400, "DSL import requires confirmation (version mismatch); unsupported.")

            app = session.get(App, result.app_id)
            if app is None:
                session.rollback()
                logger.error("Boram copy: imported app %s vanished.", result.app_id)
                abort(500, "Imported app not found.")

            # (4) Guarantee the Service API is enabled — validate_app_token 403s otherwise.
            app.enable_api = True

            # (5) Mint an app-scoped Service-API token (type='app', prefix 'app-') — the
            # exact PROV-01 issuance pattern.
            token_value = ApiToken.generate_api_key("app-", 24, session=session)
            api_token = ApiToken()
            api_token.app_id = app.id
            api_token.tenant_id = workspace_id
            api_token.token = token_value
            api_token.type = ApiTokenType.APP
            session.add(api_token)

            session.commit()

            payload: dict[str, Any] = {
                "result": "success",
                "dify_app_id": str(app.id),
                "dify_app_mode": str(app.mode),
                "app_token": token_value,
                "enable_api": app.enable_api,
            }
            return dump_response(CopyAppResponse, payload)
