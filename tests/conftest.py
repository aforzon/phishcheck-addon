"""Shared test fixtures for PhishCheck test suite."""

import os
import sys
import tempfile
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Override config before importing anything else
os.environ['DATABASE_PATH'] = ''  # Will be overridden per-test
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['DEMO_USERNAME'] = 'admin'
os.environ['DEMO_PASSWORD'] = 'testpass'
os.environ['ENABLE_URL_DETONATION'] = 'False'
os.environ['ENABLE_CISO_ALERTS'] = 'False'
os.environ['URLSCAN_API_KEY'] = ''


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary SQLite database for testing."""
    db_path = str(tmp_path / 'test.db')
    os.environ['DATABASE_PATH'] = db_path

    # Reimport config to pick up new DATABASE_PATH
    import config
    config.DATABASE_PATH = db_path

    import models
    models.init_db()

    yield db_path


@pytest.fixture
def app(tmp_db):
    """Create Flask test app with temporary database."""
    import config
    config.DATABASE_PATH = tmp_db

    # Reset the analyzer singleton so it uses fresh config
    import analyzer
    analyzer._analyzer = None

    from app import app as flask_app
    flask_app.config['TESTING'] = True
    flask_app.config['SECRET_KEY'] = 'test-secret-key'
    return flask_app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """Authenticated Flask test client."""
    client.post('/login', data={
        'username': 'admin',
        'password': 'testpass'
    })
    return client


@pytest.fixture
def analyzer_instance(tmp_db):
    """Fresh EmailAnalyzer instance."""
    import analyzer as analyzer_mod
    analyzer_mod._analyzer = None
    return analyzer_mod.EmailAnalyzer()
