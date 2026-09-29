"""Shared pytest configuration.

Every test receives a fresh database so tests do not depend on
execution order or data left behind by another test.
"""

import pytest

from fog.database import Base, engine


@pytest.fixture(autouse=True)
def reset_test_database():
    """Recreate all SQLite tables before every test."""

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    yield