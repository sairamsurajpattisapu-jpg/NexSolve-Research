import os

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///./test-upload.db")

from model_service.database import Base, _engine


def pytest_sessionstart(session):
    del session
    Base.metadata.create_all(_engine())