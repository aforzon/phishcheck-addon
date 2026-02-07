"""Tests for Flask API routes and dashboard."""

import json
import pytest
from unittest.mock import patch, MagicMock


# ═══════════════════════════════════════════════════════════════════════════════
# Health Check
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealthCheck:
    def test_health_endpoint(self, client):
        resp = client.get('/health')
        assert resp.status_code == 200
        assert resp.get_json()['status'] == 'ok'


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuth:
    def test_login_page_renders(self, client):
        resp = client.get('/login')
        assert resp.status_code == 200

    def test_login_success(self, client):
        resp = client.post('/login', data={
            'username': 'admin',
            'password': 'testpass'
        }, follow_redirects=False)
        assert resp.status_code == 302  # Redirect to dashboard

    def test_login_failure(self, client):
        resp = client.post('/login', data={
            'username': 'admin',
            'password': 'wrongpassword'
        })
        assert resp.status_code == 200
        assert b'Invalid credentials' in resp.data

    def test_dashboard_requires_login(self, client):
        resp = client.get('/', follow_redirects=False)
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_logout(self, auth_client):
        resp = auth_client.get('/logout', follow_redirects=False)
        assert resp.status_code == 302
        # Should require login again
        resp = auth_client.get('/', follow_redirects=False)
        assert resp.status_code == 302


# ═══════════════════════════════════════════════════════════════════════════════
# API: Check Email
# ═══════════════════════════════════════════════════════════════════════════════

class TestApiCheck:
    @patch('app.get_graph_client', return_value=None)
    def test_check_phishing_email(self, mock_graph, client):
        resp = client.post('/api/check', json={
            'sender': 'scammer@evil.xyz',
            'subject': 'Urgent: Verify your account',
            'headers': 'Authentication-Results: spf=fail; dkim=fail; dmarc=fail\nX-Forefront-Antispam-Report: CAT:PHSH;SCL:9',
            'body_html': '<p>Dear Customer, click here to verify your password immediately.</p>',
            'submitted_by': 'user@forzon.ca',
            'method': 'addon'
        })
        data = resp.get_json()
        assert resp.status_code == 200
        assert data['verdict'] in ('phishing', 'suspicious')
        assert data['confidence'] > 0
        assert isinstance(data['signals'], list)
        assert 'submission_id' in data

    @patch('app.get_graph_client', return_value=None)
    def test_check_safe_email(self, mock_graph, client):
        resp = client.post('/api/check', json={
            'sender': 'noreply@microsoft.com',
            'subject': 'Your monthly report',
            'headers': 'Authentication-Results: spf=pass; dkim=pass; dmarc=pass',
            'body_html': '<p>Hi John, here is your report.</p>',
            'method': 'addon'
        })
        data = resp.get_json()
        assert resp.status_code == 200
        assert data['verdict'] == 'safe'

    def test_check_missing_json(self, client):
        resp = client.post('/api/check', content_type='application/json')
        assert resp.status_code == 400

    def test_check_missing_sender(self, client):
        resp = client.post('/api/check', json={
            'subject': 'Test',
            'headers': '',
            'body_html': ''
        })
        assert resp.status_code == 400
        assert 'sender' in resp.get_json()['error'].lower()

    @patch('app.get_graph_client', return_value=None)
    def test_check_minimal_fields(self, mock_graph, client):
        """Should work with just a sender."""
        resp = client.post('/api/check', json={
            'sender': 'test@example.com'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'verdict' in data

    @patch('app.get_graph_client', return_value=None)
    def test_check_returns_signals(self, mock_graph, client):
        resp = client.post('/api/check', json={
            'sender': 'phish@paypa1.xyz',
            'headers': 'Authentication-Results: spf=fail',
            'body_html': '<p>Verify your password now!</p>',
            'subject': 'Account suspended'
        })
        data = resp.get_json()
        assert len(data['signals']) > 0
        for signal in data['signals']:
            assert 'name' in signal
            assert 'description' in signal
            assert 'weight' in signal


# ═══════════════════════════════════════════════════════════════════════════════
# API: Feedback
# ═══════════════════════════════════════════════════════════════════════════════

class TestApiFeedback:
    def _create_submission(self, client):
        with patch('app.get_graph_client', return_value=None):
            resp = client.post('/api/check', json={
                'sender': 'test@example.com',
                'subject': 'Test',
                'headers': '',
                'body_html': ''
            })
            return resp.get_json()['submission_id']

    def test_submit_feedback_correct(self, client):
        sid = self._create_submission(client)
        resp = client.post(f'/api/feedback/{sid}', json={
            'user_email': 'user@test.com',
            'user_says': 'correct'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'received'

    def test_submit_feedback_false_positive(self, client):
        sid = self._create_submission(client)
        resp = client.post(f'/api/feedback/{sid}', json={
            'user_email': 'user@test.com',
            'user_says': 'false_positive',
            'reason': 'Known vendor',
            'notes': 'Verified by phone'
        })
        assert resp.status_code == 200

    def test_feedback_nonexistent_submission(self, client):
        resp = client.post('/api/feedback/nonexistent-id', json={
            'user_email': 'user@test.com',
            'user_says': 'correct'
        })
        assert resp.status_code == 404

    def test_feedback_page_yes(self, client):
        sid = self._create_submission(client)
        resp = client.get(f'/feedback/{sid}?correct=yes')
        assert resp.status_code == 200
        assert b'Thank you' in resp.data

    def test_feedback_page_no(self, client):
        sid = self._create_submission(client)
        resp = client.get(f'/feedback/{sid}?correct=no')
        assert resp.status_code == 200

    def test_feedback_page_nonexistent(self, client):
        resp = client.get('/feedback/nonexistent?correct=yes')
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# API: Whitelist / Blacklist
# ═══════════════════════════════════════════════════════════════════════════════

class TestApiWhitelistBlacklist:
    def test_add_whitelist_requires_login(self, client):
        resp = client.post('/api/whitelist', json={
            'type': 'domain',
            'value': 'safe.com',
            'reason': 'Trusted'
        })
        assert resp.status_code == 302  # Redirects to login

    def test_add_whitelist_authenticated(self, auth_client):
        resp = auth_client.post('/api/whitelist', json={
            'type': 'domain',
            'value': 'safe.com',
            'reason': 'Trusted partner'
        })
        assert resp.status_code == 200
        assert 'id' in resp.get_json()

    def test_remove_whitelist(self, auth_client):
        resp = auth_client.post('/api/whitelist', json={
            'type': 'domain',
            'value': 'temp.com',
            'reason': 'Test'
        })
        entry_id = resp.get_json()['id']

        resp = auth_client.delete(f'/api/whitelist/{entry_id}')
        assert resp.status_code == 200
        assert resp.get_json()['status'] == 'removed'

    def test_add_blacklist(self, auth_client):
        resp = auth_client.post('/api/blacklist', json={
            'type': 'domain',
            'value': 'evil.com',
            'reason': 'Known phishing'
        })
        assert resp.status_code == 200

    def test_remove_blacklist(self, auth_client):
        resp = auth_client.post('/api/blacklist', json={
            'type': 'domain',
            'value': 'temp-evil.com',
            'reason': 'Test'
        })
        entry_id = resp.get_json()['id']

        resp = auth_client.delete(f'/api/blacklist/{entry_id}')
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# API: Stats
# ═══════════════════════════════════════════════════════════════════════════════

class TestApiStats:
    def test_stats_requires_login(self, client):
        resp = client.get('/api/stats')
        assert resp.status_code == 302

    def test_stats_authenticated(self, auth_client):
        resp = auth_client.get('/api/stats')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'total' in data

    def test_stats_custom_days(self, auth_client):
        resp = auth_client.get('/api/stats?days=7')
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# API: URL Detonation
# ═══════════════════════════════════════════════════════════════════════════════

class TestApiDetonate:
    def test_detonate_requires_login(self, client):
        resp = client.post('/api/detonate', json={'url': 'http://example.com'})
        assert resp.status_code == 302

    def test_detonate_no_api_key(self, auth_client):
        resp = auth_client.post('/api/detonate', json={'url': 'http://test.com'})
        assert resp.status_code == 503

    def test_detonate_missing_url(self, auth_client):
        import config
        config.URLSCAN_API_KEY = 'fake-key'
        resp = auth_client.post('/api/detonate', json={})
        assert resp.status_code == 400
        config.URLSCAN_API_KEY = ''

    def test_detonate_invalid_url(self, auth_client):
        import config
        config.URLSCAN_API_KEY = 'fake-key'
        resp = auth_client.post('/api/detonate', json={'url': 'not-a-url'})
        assert resp.status_code == 400
        config.URLSCAN_API_KEY = ''

    def test_list_detonations_empty(self, auth_client):
        import config
        config.DETONATION_OUTPUT_DIR = '/tmp/nonexistent-detonations-dir'
        resp = auth_client.get('/api/detonations')
        assert resp.status_code == 200
        assert resp.get_json()['detonations'] == []


# ═══════════════════════════════════════════════════════════════════════════════
# Dashboard Pages (Smoke Tests)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDashboardPages:
    def test_dashboard_renders(self, auth_client):
        resp = auth_client.get('/')
        assert resp.status_code == 200

    def test_submissions_page(self, auth_client):
        resp = auth_client.get('/submissions')
        assert resp.status_code == 200

    def test_campaigns_page(self, auth_client):
        resp = auth_client.get('/campaigns')
        assert resp.status_code == 200

    def test_accuracy_page(self, auth_client):
        resp = auth_client.get('/accuracy')
        assert resp.status_code == 200

    def test_submissions_pagination(self, auth_client):
        resp = auth_client.get('/submissions?page=2')
        assert resp.status_code == 200

    def test_submissions_filter_verdict(self, auth_client):
        resp = auth_client.get('/submissions?verdict=phishing')
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# Addon Serving
# ═══════════════════════════════════════════════════════════════════════════════

class TestAddonServing:
    def test_serve_manifest(self, client):
        resp = client.get('/addon/manifest.xml')
        assert resp.status_code == 200
        assert 'xml' in resp.content_type

    def test_serve_taskpane(self, client):
        resp = client.get('/addon/taskpane.html')
        assert resp.status_code == 200
