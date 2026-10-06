"""The per-account lockout: wrong passwords for a local account counted in
the database, so the count holds across replicas and restarts."""

import uuid
from datetime import timedelta

from sqlalchemy import case, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..models import User


async def count_failure(db: AsyncSession, user_id: uuid.UUID) -> bool:
    """Counts one wrong password against an account, locking it at the limit.
    True if this one locked it.

    One statement, adding to what the database holds rather than writing back
    a count read earlier, so wrong passwords that arrive together are each
    counted, and the account locks at the limit however they arrive."""
    settings = get_settings()
    reached = User.failed_logins + 1 >= settings.login_max_failures
    row = (await db.execute(
        update(User).where(User.id == user_id)
        .values(failed_logins=case((reached, 0), else_=User.failed_logins + 1),
                locked_until=case((reached, func.now() + timedelta(minutes=settings.login_lockout_minutes)),
                                  else_=User.locked_until))
        .returning(User.failed_logins, User.locked_until)
        .execution_options(synchronize_session=False))).first()
    return bool(row and row[0] == 0 and row[1] is not None)
