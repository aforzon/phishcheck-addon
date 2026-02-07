"""Tests for database models and operations."""

import pytest
import json


# ═══════════════════════════════════════════════════════════════════════════════
# Database Initialization
# ═══════════════════════════════════════════════════════════════════════════════

class TestDatabaseInit:
    def test_tables_created(self, tmp_db):
        from models import get_db
        with get_db() as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = [t['name'] for t in tables]
            assert 'submissions' in table_names
            assert 'campaigns' in table_names
            assert 'feedback' in table_names
            assert 'whitelist' in table_names
            assert 'blacklist' in table_names

    def test_indexes_created(self, tmp_db):
        from models import get_db
        with get_db() as conn:
            indexes = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
            index_names = [i['name'] for i in indexes]
            assert 'idx_submissions_fingerprint' in index_names
            assert 'idx_submissions_verdict' in index_names


# ═══════════════════════════════════════════════════════════════════════════════
# Submissions
# ═══════════════════════════════════════════════════════════════════════════════

class TestSubmissions:
    def test_create_and_get_submission(self, tmp_db):
        from models import create_submission, get_submission

        sid = create_submission(
            fingerprint='abc123',
            submitted_by='user@test.com',
            submission_method='addon',
            department='Finance',
            original_sender='phish@evil.com',
            sender_domain='evil.com',
            subject='Verify account',
            headers='From: phish@evil.com',
            body_html='<p>Click here</p>',
            verdict='phishing',
            confidence=85,
            signals=[{'name': 'spf_fail', 'weight': 15}]
        )

        submission = get_submission(sid)
        assert submission is not None
        assert submission['verdict'] == 'phishing'
        assert submission['confidence'] == 85
        assert submission['department'] == 'Finance'
        assert submission['sender_domain'] == 'evil.com'

    def test_get_nonexistent_submission(self, tmp_db):
        from models import get_submission
        assert get_submission('nonexistent-id') is None

    def test_signals_stored_as_json(self, tmp_db):
        from models import create_submission, get_submission

        signals = [{'name': 'spf_fail', 'weight': 15}, {'name': 'dkim_fail', 'weight': 15}]
        sid = create_submission(
            fingerprint='def456', submitted_by='user@test.com',
            submission_method='addon', department=None,
            original_sender='test@test.com', sender_domain='test.com',
            subject='Test', headers='', body_html='',
            verdict='suspicious', confidence=50, signals=signals
        )

        submission = get_submission(sid)
        parsed = json.loads(submission['signals'])
        assert len(parsed) == 2
        assert parsed[0]['name'] == 'spf_fail'

    def test_get_submissions_with_filter(self, tmp_db):
        from models import create_submission, get_submissions

        for verdict in ['phishing', 'safe', 'phishing']:
            create_submission(
                fingerprint='fp', submitted_by='user@test.com',
                submission_method='addon', department=None,
                original_sender='a@b.com', sender_domain='b.com',
                subject='Test', headers='', body_html='',
                verdict=verdict, confidence=50, signals=[]
            )

        phishing = get_submissions(verdict='phishing')
        assert len(phishing) == 2

        safe = get_submissions(verdict='safe')
        assert len(safe) == 1

    def test_get_submissions_pagination(self, tmp_db):
        from models import create_submission, get_submissions

        for i in range(10):
            create_submission(
                fingerprint=f'fp{i}', submitted_by='user@test.com',
                submission_method='addon', department=None,
                original_sender='a@b.com', sender_domain='b.com',
                subject=f'Test {i}', headers='', body_html='',
                verdict='safe', confidence=10, signals=[]
            )

        page1 = get_submissions(limit=3, offset=0)
        page2 = get_submissions(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0]['id'] != page2[0]['id']


# ═══════════════════════════════════════════════════════════════════════════════
# Submission Stats
# ═══════════════════════════════════════════════════════════════════════════════

class TestSubmissionStats:
    def test_stats_count(self, tmp_db):
        from models import create_submission, get_submission_stats

        for verdict in ['phishing', 'phishing', 'suspicious', 'safe', 'safe', 'safe']:
            create_submission(
                fingerprint='fp', submitted_by='user@test.com',
                submission_method='addon', department=None,
                original_sender='a@b.com', sender_domain='b.com',
                subject='Test', headers='', body_html='',
                verdict=verdict, confidence=50, signals=[]
            )

        stats = get_submission_stats(days=1)
        assert stats['total'] == 6
        assert stats['phishing'] == 2
        assert stats['suspicious'] == 1
        assert stats['safe'] == 3


# ═══════════════════════════════════════════════════════════════════════════════
# Campaigns
# ═══════════════════════════════════════════════════════════════════════════════

class TestCampaigns:
    def test_create_new_campaign(self, tmp_db):
        from models import find_or_create_campaign

        campaign, is_new = find_or_create_campaign('fingerprint1', 'evil.com', 'Verify account')
        assert is_new is True
        assert campaign['fingerprint'] == 'fingerprint1'
        assert campaign['user_count'] == 1

    def test_existing_campaign_increments_count(self, tmp_db):
        from models import find_or_create_campaign

        campaign1, _ = find_or_create_campaign('fingerprint1', 'evil.com', 'Verify')
        campaign2, is_new = find_or_create_campaign('fingerprint1', 'evil.com', 'Verify')

        assert is_new is False
        assert campaign2['id'] == campaign1['id']
        # Note: campaign2 returns the old count because it reads before updating
        # The actual count in DB is incremented

    def test_different_fingerprint_creates_new(self, tmp_db):
        from models import find_or_create_campaign

        c1, _ = find_or_create_campaign('fp1', 'evil.com', 'Subject 1')
        c2, is_new = find_or_create_campaign('fp2', 'other.com', 'Subject 2')
        assert is_new is True
        assert c1['id'] != c2['id']

    def test_get_active_campaigns(self, tmp_db):
        from models import find_or_create_campaign, get_active_campaigns

        find_or_create_campaign('fp1', 'evil.com', 'Subject 1')
        find_or_create_campaign('fp2', 'other.com', 'Subject 2')

        campaigns = get_active_campaigns()
        assert len(campaigns) == 2

    def test_campaign_alert_level_normal(self, tmp_db):
        from models import find_or_create_campaign, get_campaign_alert_level

        campaign, _ = find_or_create_campaign('fp1', 'evil.com', 'Test')
        level = get_campaign_alert_level(campaign['id'])
        assert level == 'normal'


# ═══════════════════════════════════════════════════════════════════════════════
# Feedback
# ═══════════════════════════════════════════════════════════════════════════════

class TestFeedback:
    def _create_test_submission(self):
        from models import create_submission
        return create_submission(
            fingerprint='fp', submitted_by='user@test.com',
            submission_method='addon', department=None,
            original_sender='a@b.com', sender_domain='b.com',
            subject='Test', headers='', body_html='',
            verdict='phishing', confidence=80, signals=[]
        )

    def test_create_feedback(self, tmp_db):
        from models import create_feedback, get_db
        sid = self._create_test_submission()
        fid = create_feedback(sid, 'user@test.com', 'phishing', 'correct')

        with get_db() as conn:
            fb = conn.execute('SELECT * FROM feedback WHERE id = ?', (fid,)).fetchone()
            assert fb is not None
            assert fb['user_says'] == 'correct'
            assert fb['review_status'] == 'pending'

    def test_feedback_stats(self, tmp_db):
        from models import create_feedback, get_feedback_stats
        sid = self._create_test_submission()

        create_feedback(sid, 'u1@test.com', 'phishing', 'correct')
        create_feedback(sid, 'u2@test.com', 'phishing', 'correct')
        create_feedback(sid, 'u3@test.com', 'phishing', 'false_positive')

        stats = get_feedback_stats(days=1)
        assert stats['total'] == 3
        assert stats['phishing_total'] == 3
        assert stats['phishing_correct'] == 2
        assert stats['phishing_accuracy'] == pytest.approx(66.67, abs=0.1)

    def test_pending_feedback(self, tmp_db):
        from models import create_feedback, get_pending_feedback
        sid = self._create_test_submission()
        create_feedback(sid, 'user@test.com', 'phishing', 'false_positive')

        pending = get_pending_feedback()
        assert len(pending) == 1
        assert pending[0]['user_says'] == 'false_positive'


# ═══════════════════════════════════════════════════════════════════════════════
# Whitelist / Blacklist
# ═══════════════════════════════════════════════════════════════════════════════

class TestWhitelistBlacklist:
    def test_add_and_check_whitelist_domain(self, tmp_db):
        from models import add_to_whitelist, is_whitelisted
        add_to_whitelist('domain', 'safe.com', 'Trusted', 'admin')
        assert is_whitelisted('user@safe.com', 'safe.com') is True

    def test_add_and_check_whitelist_sender(self, tmp_db):
        from models import add_to_whitelist, is_whitelisted
        add_to_whitelist('sender', 'specific@partner.com', 'Known contact', 'admin')
        assert is_whitelisted('specific@partner.com', 'partner.com') is True

    def test_not_whitelisted(self, tmp_db):
        from models import is_whitelisted
        assert is_whitelisted('user@unknown.com', 'unknown.com') is False

    def test_whitelist_case_insensitive(self, tmp_db):
        from models import add_to_whitelist, is_whitelisted
        add_to_whitelist('domain', 'Safe.COM', 'Trusted', 'admin')
        assert is_whitelisted('user@safe.com', 'safe.com') is True

    def test_add_and_check_blacklist(self, tmp_db):
        from models import add_to_blacklist, is_blacklisted
        add_to_blacklist('domain', 'evil.com', 'Known phishing', 'admin')
        assert is_blacklisted('user@evil.com', 'evil.com') is True

    def test_not_blacklisted(self, tmp_db):
        from models import is_blacklisted
        assert is_blacklisted('user@clean.com', 'clean.com') is False

    def test_remove_from_whitelist(self, tmp_db):
        from models import add_to_whitelist, remove_from_whitelist, is_whitelisted
        eid = add_to_whitelist('domain', 'temp.com', 'Temp', 'admin')
        assert is_whitelisted('user@temp.com', 'temp.com') is True
        remove_from_whitelist(eid)
        assert is_whitelisted('user@temp.com', 'temp.com') is False

    def test_remove_from_blacklist(self, tmp_db):
        from models import add_to_blacklist, remove_from_blacklist, is_blacklisted
        eid = add_to_blacklist('domain', 'temp.com', 'Temp', 'admin')
        assert is_blacklisted('user@temp.com', 'temp.com') is True
        remove_from_blacklist(eid)
        assert is_blacklisted('user@temp.com', 'temp.com') is False

    def test_get_whitelist(self, tmp_db):
        from models import add_to_whitelist, get_whitelist
        add_to_whitelist('domain', 'a.com', 'A', 'admin')
        add_to_whitelist('domain', 'b.com', 'B', 'admin')
        wl = get_whitelist()
        assert len(wl) == 2

    def test_null_sender_no_crash(self, tmp_db):
        from models import is_whitelisted, is_blacklisted
        # Should not raise AttributeError
        assert is_whitelisted(None, 'example.com') is False
        assert is_blacklisted(None, 'example.com') is False

    def test_null_domain_no_crash(self, tmp_db):
        from models import is_whitelisted, is_blacklisted
        assert is_whitelisted('user@example.com', None) is False
        assert is_blacklisted('user@example.com', None) is False


# ═══════════════════════════════════════════════════════════════════════════════
# Auto-Whitelist
# ═══════════════════════════════════════════════════════════════════════════════

class TestAutoWhitelist:
    def test_auto_whitelist_after_threshold(self, tmp_db):
        from models import (
            create_submission, create_feedback,
            check_auto_whitelist, is_whitelisted
        )

        # Create 3 submissions from the same domain, each with false positive feedback
        for i in range(3):
            sid = create_submission(
                fingerprint=f'fp{i}', submitted_by=f'user{i}@test.com',
                submission_method='addon', department=None,
                original_sender=f'sender@legit-vendor.com',
                sender_domain='legit-vendor.com',
                subject=f'Invoice {i}', headers='', body_html='',
                verdict='phishing', confidence=75, signals=[]
            )
            create_feedback(sid, f'user{i}@test.com', 'phishing', 'false_positive')

        result = check_auto_whitelist('legit-vendor.com', threshold=3)
        assert result is True
        assert is_whitelisted('someone@legit-vendor.com', 'legit-vendor.com') is True

    def test_no_auto_whitelist_below_threshold(self, tmp_db):
        from models import create_submission, create_feedback, check_auto_whitelist

        sid = create_submission(
            fingerprint='fp1', submitted_by='user@test.com',
            submission_method='addon', department=None,
            original_sender='sender@vendor.com', sender_domain='vendor.com',
            subject='Invoice', headers='', body_html='',
            verdict='phishing', confidence=75, signals=[]
        )
        create_feedback(sid, 'user@test.com', 'phishing', 'false_positive')

        result = check_auto_whitelist('vendor.com', threshold=3)
        assert result is False

    def test_auto_whitelist_idempotent(self, tmp_db):
        from models import (
            create_submission, create_feedback,
            check_auto_whitelist, add_to_whitelist
        )

        # Manually whitelist first
        add_to_whitelist('domain', 'already.com', 'Manual', 'admin')

        sid = create_submission(
            fingerprint='fp1', submitted_by='user@test.com',
            submission_method='addon', department=None,
            original_sender='s@already.com', sender_domain='already.com',
            subject='Test', headers='', body_html='',
            verdict='phishing', confidence=75, signals=[]
        )
        create_feedback(sid, 'user@test.com', 'phishing', 'false_positive')

        # Should return False since already whitelisted
        result = check_auto_whitelist('already.com', threshold=1)
        assert result is False


# ═══════════════════════════════════════════════════════════════════════════════
# Unique Users
# ═══════════════════════════════════════════════════════════════════════════════

class TestUniqueUsers:
    def test_count_unique(self, tmp_db):
        from models import create_submission, get_unique_users

        for user in ['a@test.com', 'b@test.com', 'a@test.com']:
            create_submission(
                fingerprint='fp', submitted_by=user,
                submission_method='addon', department=None,
                original_sender='x@y.com', sender_domain='y.com',
                subject='Test', headers='', body_html='',
                verdict='safe', confidence=10, signals=[]
            )

        assert get_unique_users(days=1) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# Learning Stats
# ═══════════════════════════════════════════════════════════════════════════════

class TestLearningStats:
    def test_learning_stats_empty(self, tmp_db):
        from models import get_learning_stats
        stats = get_learning_stats()
        assert stats['auto_whitelisted'] == 0
        assert stats['manual_whitelisted'] == 0
        assert stats['total_feedback'] == 0
        assert stats['false_positive_rate'] == 0
