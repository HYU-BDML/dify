"""Unit tests for controllers.web.app endpoints."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from werkzeug.exceptions import Unauthorized

from controllers.common.errors import InvalidArgumentError
from controllers.web.app import AppAccessMode, AppMeta, AppParameterApi, AppWebAuthPermission
from controllers.web.error import (
    AgentNotPublishedError,
    AppUnavailableError,
    WebAppAccessServiceUnavailableError,
    WebAppAuthRequiredError,
    WebAppNotFoundError,
)
from core.app.apps.agent_app.errors import AgentAppNotPublishedError
from enums import WebAppAccessMode
from services.webapp_access_query_service import (
    WebAppAccessAppNotFoundError,
    WebAppAccessReferenceRequiredError,
    WebAppAccessUnavailableError,
)


# ---------------------------------------------------------------------------
# AppParameterApi
# ---------------------------------------------------------------------------
class TestAppParameterApi:
    def test_advanced_chat_mode_uses_workflow(self, app: Flask) -> None:
        features_dict = {"opening_statement": "Hello"}
        workflow = SimpleNamespace(
            features_dict=features_dict,
            user_input_form=lambda to_old_structure=False: [],
        )
        app_model = SimpleNamespace(
            mode="advanced-chat",
            workflow_with_session=lambda *, session: workflow,
        )

        with (
            app.test_request_context("/parameters"),
            patch("controllers.web.app.get_parameters_from_feature_dict", return_value={}) as mock_params,
            patch("controllers.web.app.fields.Parameters") as mock_fields,
        ):
            mock_fields.model_validate.return_value.model_dump.return_value = {"result": "ok"}
            result = AppParameterApi().get(app_model, SimpleNamespace())

        mock_params.assert_called_once_with(features_dict=features_dict, user_input_form=[])
        assert result == {"result": "ok"}

    def test_workflow_mode_uses_workflow(self, app: Flask) -> None:
        features_dict = {}
        workflow = SimpleNamespace(
            features_dict=features_dict,
            user_input_form=lambda to_old_structure=False: [{"var": "x"}],
        )
        app_model = SimpleNamespace(
            mode="workflow",
            workflow_with_session=lambda *, session: workflow,
        )

        with (
            app.test_request_context("/parameters"),
            patch("controllers.web.app.get_parameters_from_feature_dict", return_value={}) as mock_params,
            patch("controllers.web.app.fields.Parameters") as mock_fields,
        ):
            mock_fields.model_validate.return_value.model_dump.return_value = {}
            AppParameterApi().get(app_model, SimpleNamespace())

        mock_params.assert_called_once_with(features_dict=features_dict, user_input_form=[{"var": "x"}])

    def test_advanced_chat_mode_no_workflow_raises(self, app: Flask) -> None:
        app_model = SimpleNamespace(
            mode="advanced-chat",
            workflow_with_session=lambda *, session: None,
        )
        with app.test_request_context("/parameters"):
            with pytest.raises(AppUnavailableError):
                AppParameterApi().get(app_model, SimpleNamespace())

    def test_standard_mode_uses_app_model_config(self, app: Flask) -> None:
        config = SimpleNamespace(to_dict=lambda **_kwargs: {"user_input_form": [{"var": "y"}], "key": "val"})
        app_model = SimpleNamespace(
            id="app-1",
            mode="chat",
            app_model_config_with_session=lambda *, session: config,
        )

        with (
            app.test_request_context("/parameters"),
            patch("controllers.web.app.get_parameters_from_feature_dict", return_value={}) as mock_params,
            patch("controllers.web.app.fields.Parameters") as mock_fields,
            patch("controllers.web.app.load_annotation_reply_config", return_value={"enabled": False}),
        ):
            mock_fields.model_validate.return_value.model_dump.return_value = {}
            AppParameterApi().get(app_model, SimpleNamespace())

        call_kwargs = mock_params.call_args
        assert call_kwargs.kwargs["user_input_form"] == [{"var": "y"}]

    def test_standard_mode_no_config_raises(self, app: Flask) -> None:
        app_model = SimpleNamespace(
            mode="chat",
            app_model_config_with_session=lambda *, session: None,
        )
        with app.test_request_context("/parameters"):
            with pytest.raises(AppUnavailableError):
                AppParameterApi().get(app_model, SimpleNamespace())

    def test_agent_mode_unpublished_raises_friendly_error(self, app: Flask) -> None:
        app_model = SimpleNamespace(mode="agent")
        with (
            app.test_request_context("/parameters"),
            patch(
                "controllers.web.app.get_published_agent_app_feature_dict_and_user_input_form",
                side_effect=AgentAppNotPublishedError("Agent has not been published"),
            ),
        ):
            with pytest.raises(AgentNotPublishedError):
                AppParameterApi().get(app_model, SimpleNamespace())


# ---------------------------------------------------------------------------
# AppMeta
# ---------------------------------------------------------------------------
class TestAppMeta:
    @patch("controllers.web.app.AppService")
    def test_get_returns_meta(self, mock_service_cls: MagicMock, app: Flask) -> None:
        mock_service_cls.return_value.get_app_meta.return_value = {"tool_icons": {}}
        app_model = SimpleNamespace(id="app-1")

        with app.test_request_context("/meta"):
            result = AppMeta().get(app_model, SimpleNamespace())

        assert result == {"tool_icons": {}}


# ---------------------------------------------------------------------------
# AppAccessMode
# ---------------------------------------------------------------------------
class TestAppAccessMode:
    @patch("controllers.web.app.application_services")
    def test_delegates_validated_app_references(self, application_services: MagicMock, app: Flask) -> None:
        webapp_access = MagicMock()
        webapp_access.get_access_mode.return_value = WebAppAccessMode.SSO_VERIFIED
        application_services.return_value = SimpleNamespace(webapp_access=webapp_access)

        with app.test_request_context("/webapp/access-mode?appId=app-1&appCode=code-1"):
            result = AppAccessMode().get()

        assert result == {"accessMode": "sso_verified"}
        webapp_access.get_access_mode.assert_called_once_with(app_id="app-1", app_code="code-1")

    @pytest.mark.parametrize(
        ("service_error", "http_error", "expected_data"),
        [
            pytest.param(
                WebAppAccessReferenceRequiredError("appId or appCode must be provided"),
                InvalidArgumentError,
                {"code": "invalid_param", "message": "appId or appCode must be provided", "status": 400},
                id="missing-reference",
            ),
            pytest.param(
                WebAppAccessAppNotFoundError(),
                WebAppNotFoundError,
                {"code": "app_not_found", "message": "App not found.", "status": 404},
                id="app-not-found",
            ),
            pytest.param(
                WebAppAccessUnavailableError(),
                WebAppAccessServiceUnavailableError,
                {
                    "code": "web_app_access_unavailable",
                    "message": "Web app access service is unavailable.",
                    "status": 503,
                },
                id="access-unavailable",
            ),
        ],
    )
    @patch("controllers.web.app.application_services")
    def test_maps_query_errors(
        self,
        application_services: MagicMock,
        service_error: Exception,
        http_error: type[Exception],
        expected_data: dict[str, object],
        app: Flask,
    ) -> None:
        webapp_access = MagicMock()
        webapp_access.get_access_mode.side_effect = service_error
        application_services.return_value = SimpleNamespace(webapp_access=webapp_access)

        with app.test_request_context("/webapp/access-mode?appCode=code-1"):
            with pytest.raises(http_error) as raised:
                AppAccessMode().get()

        assert raised.value.data == expected_data


# ---------------------------------------------------------------------------
# AppWebAuthPermission
# ---------------------------------------------------------------------------
class TestAppWebAuthPermission:
    @patch("controllers.web.app.application_services")
    def test_returns_true_without_reading_passport_when_no_permission_check_required(
        self, application_services: MagicMock, app: Flask
    ) -> None:
        webapp_access = MagicMock()
        webapp_access.requires_permission_check.return_value = False
        application_services.return_value = SimpleNamespace(webapp_access=webapp_access)

        with (
            app.test_request_context("/webapp/permission?appId=app-1", headers={"X-App-Code": "code1"}),
            patch("controllers.web.app.extract_webapp_passport") as extract_passport,
        ):
            result = AppWebAuthPermission().get()

        assert result == {"result": True}
        webapp_access.requires_permission_check.assert_called_once_with("app-1")
        webapp_access.is_user_allowed.assert_not_called()
        extract_passport.assert_not_called()

    @pytest.mark.parametrize(
        ("decoded", "expected_user_id", "allowed"),
        [
            pytest.param({"user_id": "user-1"}, "user-1", True, id="identified-user"),
            pytest.param({}, "visitor", False, id="visitor-fallback"),
        ],
    )
    @patch("controllers.web.app.application_services")
    def test_checks_private_app_permission(
        self,
        application_services: MagicMock,
        decoded: dict[str, str],
        expected_user_id: str,
        allowed: bool,
        app: Flask,
    ) -> None:
        webapp_access = MagicMock()
        webapp_access.requires_permission_check.return_value = True
        webapp_access.is_user_allowed.return_value = allowed
        application_services.return_value = SimpleNamespace(webapp_access=webapp_access)

        with (
            app.test_request_context("/webapp/permission?appId=app-1", headers={"X-App-Code": "code1"}),
            patch("controllers.web.app.extract_webapp_passport", return_value="passport") as extract_passport,
            patch("controllers.web.app.PassportService") as passport_service,
        ):
            passport_service.return_value.verify.return_value = decoded
            result = AppWebAuthPermission().get()

        assert result == {"result": allowed}
        webapp_access.requires_permission_check.assert_called_once_with("app-1")
        extract_passport.assert_called_once()
        passport_service.return_value.verify.assert_called_once_with("passport")
        webapp_access.is_user_allowed.assert_called_once_with(user_id=expected_user_id, app_id="app-1")

    @patch("controllers.web.app.application_services")
    def test_private_app_requires_passport(self, application_services: MagicMock, app: Flask) -> None:
        webapp_access = MagicMock()
        webapp_access.requires_permission_check.return_value = True
        application_services.return_value = SimpleNamespace(webapp_access=webapp_access)

        with (
            app.test_request_context("/webapp/permission?appId=app-1", headers={"X-App-Code": "code1"}),
            patch("controllers.web.app.extract_webapp_passport", return_value=None),
            pytest.raises(WebAppAuthRequiredError) as raised,
        ):
            AppWebAuthPermission().get()

        assert raised.value.data == {
            "code": "web_sso_auth_required",
            "message": "Web app authentication required.",
            "status": 401,
        }
        webapp_access.is_user_allowed.assert_not_called()

    @pytest.mark.parametrize(
        "description",
        ["Token has expired.", "Invalid token signature.", "Invalid token."],
    )
    @patch("controllers.web.app.application_services")
    def test_invalid_passport_is_normalized_to_web_app_auth_required(
        self, application_services: MagicMock, description: str, app: Flask
    ) -> None:
        webapp_access = MagicMock()
        webapp_access.requires_permission_check.return_value = True
        application_services.return_value = SimpleNamespace(webapp_access=webapp_access)
        invalid_passport = Unauthorized(description)

        with (
            app.test_request_context("/webapp/permission?appId=app-1", headers={"X-App-Code": "code1"}),
            patch("controllers.web.app.extract_webapp_passport", return_value="passport"),
            patch("controllers.web.app.PassportService") as passport_service,
        ):
            passport_service.return_value.verify.side_effect = invalid_passport
            with pytest.raises(WebAppAuthRequiredError) as raised:
                AppWebAuthPermission().get()

        assert raised.value.data == {
            "code": "web_sso_auth_required",
            "message": "Web app authentication required.",
            "status": 401,
        }
        webapp_access.is_user_allowed.assert_not_called()

    @pytest.mark.parametrize(
        ("path", "headers"),
        [
            pytest.param("/webapp/permission", {"X-App-Code": "code1"}, id="missing-app-id"),
            pytest.param("/webapp/permission?appId=app-1", {}, id="missing-app-code"),
        ],
    )
    @patch("controllers.web.app.application_services")
    def test_raises_when_app_reference_is_missing(
        self, application_services: MagicMock, path: str, headers: dict[str, str], app: Flask
    ) -> None:
        with app.test_request_context(path, headers=headers):
            with pytest.raises(ValueError, match="appId"):
                AppWebAuthPermission().get()

        application_services.assert_not_called()
