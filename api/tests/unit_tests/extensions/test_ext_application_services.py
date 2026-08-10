from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session, sessionmaker

from enums import DeploymentEdition
from extensions.ext_application_services import build_application_services
from extensions.ext_redis import RedisClientWrapper
from repositories.account_integration_repository import SQLAlchemyAccountIntegrationRepository
from repositories.account_repository import SQLAlchemyAccountRepository
from services.account_avatar_file_gateway import SQLAlchemyAccountAvatarFileGateway


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


def test_build_application_services_wires_account_profile_repository(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
    services = build_application_services(
        database_client=sqlite_session_factory,
        deployment_edition=DeploymentEdition.COMMUNITY,
        redis=MagicMock(spec=RedisClientWrapper),
    )

    accounts = services.accounts.profile._accounts
    assert isinstance(accounts, SQLAlchemyAccountRepository)
    assert accounts._session_factory is sqlite_session_factory
    assert services.accounts.password._accounts is accounts
    integrations = services.accounts.integrations._integrations
    assert isinstance(integrations, SQLAlchemyAccountIntegrationRepository)
    assert integrations._session_factory is sqlite_session_factory
    avatar_files = services.accounts.avatar._files
    assert isinstance(avatar_files, SQLAlchemyAccountAvatarFileGateway)
    assert avatar_files._session_factory is sqlite_session_factory
