import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from models.model import AccountTrialAppRecord
from repositories.trial_app_usage_repository import TrialAppUsageRepository


def _record(
    session_factory: sessionmaker[Session],
    *,
    app_id: str,
    account_id: str,
) -> AccountTrialAppRecord | None:
    with session_factory() as session:
        return session.scalar(
            select(AccountTrialAppRecord).where(
                AccountTrialAppRecord.app_id == app_id,
                AccountTrialAppRecord.account_id == account_id,
            )
        )


def test_increment_creates_and_commits_record(sqlite_session_factory: sessionmaker[Session]) -> None:
    app_id = str(uuid.uuid4())
    account_id = str(uuid.uuid4())

    TrialAppUsageRepository(sqlite_session_factory).increment(app_id=app_id, account_id=account_id)

    record = _record(sqlite_session_factory, app_id=app_id, account_id=account_id)
    assert record is not None
    assert record.count == 1


def test_increment_updates_existing_record(sqlite_session_factory: sessionmaker[Session]) -> None:
    app_id = str(uuid.uuid4())
    account_id = str(uuid.uuid4())
    with sqlite_session_factory.begin() as session:
        session.add(AccountTrialAppRecord(app_id=app_id, account_id=account_id, count=3))

    TrialAppUsageRepository(sqlite_session_factory).increment(app_id=app_id, account_id=account_id)

    record = _record(sqlite_session_factory, app_id=app_id, account_id=account_id)
    assert record is not None
    assert record.count == 4
