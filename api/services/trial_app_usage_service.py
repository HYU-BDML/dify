"""Application service for recording recommended trial app usage."""

from typing import Protocol


class TrialAppUsageStore(Protocol):
    def increment(self, *, app_id: str, account_id: str) -> None: ...


class TrialAppUsageService:
    def __init__(self, *, usage: TrialAppUsageStore) -> None:
        self._usage = usage

    def record(self, *, app_id: str, account_id: str) -> None:
        self._usage.increment(app_id=app_id, account_id=account_id)
