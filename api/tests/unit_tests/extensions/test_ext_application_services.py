import json
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from flask import Flask
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from enums import DeploymentEdition
from extensions import ext_application_services
from extensions.ext_application_services import build_application_services
from extensions.ext_redis import RedisClientWrapper
from models.model import AccountTrialAppRecord
from services import recommended_app_catalog_gateway


@pytest.mark.parametrize(
    ("deployment_edition", "setup_completed"),
    [
        pytest.param(DeploymentEdition.CLOUD, True, id="cloud"),
        pytest.param(DeploymentEdition.COMMUNITY, False, id="community"),
        pytest.param(DeploymentEdition.ENTERPRISE, False, id="enterprise"),
    ],
)
def test_build_application_services_configures_setup_policy(
    sqlite_session_factory: sessionmaker[Session],
    deployment_edition: DeploymentEdition,
    setup_completed: bool,
) -> None:
    services = build_application_services(
        database_client=sqlite_session_factory,
        deployment_edition=deployment_edition,
        redis=MagicMock(spec=RedisClientWrapper),
    )

    assert services.setup.get_status().completed is setup_completed


def test_build_application_services_wires_builtin_schema_definitions(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
    services = build_application_services(
        database_client=sqlite_session_factory,
        deployment_edition=DeploymentEdition.COMMUNITY,
        redis=MagicMock(spec=RedisClientWrapper),
    )

    definitions = services.schema_definitions.list()

    assert definitions
    assert all({"name", "label", "schema"} <= definition.keys() for definition in definitions)


def test_build_application_services_does_not_construct_schema_manager(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
    with patch("extensions.ext_application_services.SchemaManager") as schema_manager:
        build_application_services(
            database_client=sqlite_session_factory,
            deployment_edition=DeploymentEdition.COMMUNITY,
            redis=MagicMock(spec=RedisClientWrapper),
        )

    schema_manager.assert_not_called()


def test_build_application_services_wires_trial_app_usage(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
    services = build_application_services(
        database_client=sqlite_session_factory,
        deployment_edition=DeploymentEdition.COMMUNITY,
        redis=MagicMock(spec=RedisClientWrapper),
    )
    app_id = str(uuid4())
    account_id = str(uuid4())

    services.trial_app_usage.record(app_id=app_id, account_id=account_id)

    with sqlite_session_factory() as session:
        record = session.scalar(
            select(AccountTrialAppRecord).where(
                AccountTrialAppRecord.app_id == app_id,
                AccountTrialAppRecord.account_id == account_id,
            )
        )
    assert record is not None
    assert record.count == 1


def test_build_application_services_wires_dynamic_recommended_catalog(
    app: Flask,
    sqlite_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ext_application_services.dify_config, "HOSTED_FETCH_APP_TEMPLATES_MODE", "builtin")
    services = build_application_services(
        database_client=sqlite_session_factory,
        deployment_edition=DeploymentEdition.COMMUNITY,
        redis=MagicMock(spec=RedisClientWrapper),
    )

    builtin_payload = json.dumps(
        {
            "recommended_apps": {
                "en-US": {
                    "recommended_apps": [{"app": None, "app_id": "app-1", "categories": []}],
                    "categories": [],
                }
            }
        }
    )
    with (
        app.app_context(),
        patch.object(recommended_app_catalog_gateway.Path, "read_text", return_value=builtin_payload),
    ):
        result = services.recommended_app_queries.list_recommended(
            requested_language="en-US",
            interface_language=None,
        )
    assert result.recommended_apps

    monkeypatch.setattr(ext_application_services.dify_config, "HOSTED_FETCH_APP_TEMPLATES_MODE", "invalid")
    with app.app_context(), pytest.raises(ValueError, match="invalid fetch recommended apps mode: invalid"):
        services.recommended_app_queries.list_recommended(
            requested_language="en-US",
            interface_language=None,
        )
