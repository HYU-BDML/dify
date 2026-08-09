from unittest.mock import MagicMock

from services.trial_app_usage_service import TrialAppUsageService


def test_record_delegates_to_usage_store() -> None:
    usage = MagicMock()
    service = TrialAppUsageService(usage=usage)

    service.record(app_id="app-1", account_id="account-1")

    usage.increment.assert_called_once_with(app_id="app-1", account_id="account-1")
