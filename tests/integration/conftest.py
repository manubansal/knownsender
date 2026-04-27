import os
import subprocess

import psycopg2
import pytest

_DB_URL = os.environ.get("PYTEST_DATABASE_URL")


@pytest.fixture(scope="session")
def db_url():
    if not _DB_URL:
        pytest.skip("PYTEST_DATABASE_URL not set — skipping integration tests")
    return _DB_URL


@pytest.fixture(scope="session")
def _run_migrations(db_url):
    env = {**os.environ, "DATABASE_URL": db_url}
    subprocess.run(["alembic", "upgrade", "head"], env=env, check=True)


@pytest.fixture
def db_conn(db_url, _run_migrations):
    conn = psycopg2.connect(db_url)
    conn.autocommit = False
    yield conn
    conn.rollback()
    conn.close()
