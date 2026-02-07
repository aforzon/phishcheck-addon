import sqlite3
import uuid
import json
from datetime import datetime
from contextlib import contextmanager


def get_db_path():
    from config import DATABASE_PATH
    return DATABASE_PATH


@contextmanager
def get_db():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.executescript('''
            -- All checked emails
            CREATE TABLE IF NOT EXISTS submissions (
                id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                submitted_by TEXT,
                submission_method TEXT,
                department TEXT,
                original_sender TEXT,
                sender_domain TEXT,
                subject TEXT,
                headers TEXT,
                body_html TEXT,
                verdict TEXT,
                confidence INTEGER,
                signals TEXT,
                campaign_id TEXT,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
            );

            -- Detected campaigns
            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                name TEXT,
                fingerprint TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                user_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                indicators TEXT
            );

            -- User feedback
            CREATE TABLE IF NOT EXISTS feedback (
                id TEXT PRIMARY KEY,
                submission_id TEXT,
                user_email TEXT,
                original_verdict TEXT,
                user_says TEXT,
                reason TEXT,
                notes TEXT,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_by TEXT,
                reviewed_at TIMESTAMP,
                review_status TEXT DEFAULT 'pending',
                added_to_whitelist INTEGER DEFAULT 0,
                FOREIGN KEY (submission_id) REFERENCES submissions(id)
            );

            -- Trusted senders/domains
            CREATE TABLE IF NOT EXISTS whitelist (
                id TEXT PRIMARY KEY,
                type TEXT,
                value TEXT,
                reason TEXT,
                added_by TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Blacklisted senders/domains
            CREATE TABLE IF NOT EXISTS blacklist (
                id TEXT PRIMARY KEY,
                type TEXT,
                value TEXT,
                reason TEXT,
                added_by TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_submissions_fingerprint ON submissions(fingerprint);
            CREATE INDEX IF NOT EXISTS idx_submissions_submitted_at ON submissions(submitted_at);
            CREATE INDEX IF NOT EXISTS idx_submissions_verdict ON submissions(verdict);
            CREATE INDEX IF NOT EXISTS idx_submissions_department ON submissions(department);
            CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
            CREATE INDEX IF NOT EXISTS idx_feedback_review_status ON feedback(review_status);
        ''')
        conn.commit()


# Submission functions
def create_submission(fingerprint, submitted_by, submission_method, department,
                      original_sender, sender_domain, subject, headers, body_html,
                      verdict, confidence, signals, campaign_id=None):
    submission_id = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute('''
            INSERT INTO submissions (id, fingerprint, submitted_by, submission_method,
                department, original_sender, sender_domain, subject, headers, body_html,
                verdict, confidence, signals, campaign_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (submission_id, fingerprint, submitted_by, submission_method,
              department, original_sender, sender_domain, subject, headers, body_html,
              verdict, confidence, json.dumps(signals), campaign_id))
        conn.commit()
    return submission_id


def get_submission(submission_id):
    with get_db() as conn:
        row = conn.execute('SELECT * FROM submissions WHERE id = ?', (submission_id,)).fetchone()
        if row:
            return dict(row)
    return None


def get_submissions(limit=100, offset=0, verdict=None, department=None):
    with get_db() as conn:
        query = 'SELECT * FROM submissions WHERE 1=1'
        params = []
        if verdict:
            query += ' AND verdict = ?'
            params.append(verdict)
        if department:
            query += ' AND department = ?'
            params.append(department)
        query += ' ORDER BY submitted_at DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def get_submission_stats(days=30):
    with get_db() as conn:
        stats = {}

        # Total counts
        stats['total'] = conn.execute('''
            SELECT COUNT(*) FROM submissions
            WHERE submitted_at >= datetime('now', ?)
        ''', (f'-{days} days',)).fetchone()[0]

        # By verdict
        for verdict in ['phishing', 'suspicious', 'safe']:
            stats[verdict] = conn.execute('''
                SELECT COUNT(*) FROM submissions
                WHERE verdict = ? AND submitted_at >= datetime('now', ?)
            ''', (verdict, f'-{days} days')).fetchone()[0]

        # By department
        dept_rows = conn.execute('''
            SELECT department, COUNT(*) as count FROM submissions
            WHERE submitted_at >= datetime('now', ?) AND department IS NOT NULL
            GROUP BY department ORDER BY count DESC LIMIT 10
        ''', (f'-{days} days',)).fetchall()
        stats['by_department'] = [dict(row) for row in dept_rows]

        # Daily volume (last 7 days)
        daily_rows = conn.execute('''
            SELECT date(submitted_at) as date, COUNT(*) as count,
                   SUM(CASE WHEN verdict = 'phishing' THEN 1 ELSE 0 END) as phishing
            FROM submissions
            WHERE submitted_at >= datetime('now', '-7 days')
            GROUP BY date(submitted_at) ORDER BY date
        ''').fetchall()
        stats['daily'] = [dict(row) for row in daily_rows]

        return stats


# Campaign functions
def find_or_create_campaign(fingerprint, sender_domain, subject):
    with get_db() as conn:
        # Check for existing active campaign
        existing = conn.execute('''
            SELECT * FROM campaigns WHERE fingerprint = ? AND status = 'active'
        ''', (fingerprint,)).fetchone()

        if existing:
            # Update existing campaign
            conn.execute('''
                UPDATE campaigns SET last_seen = CURRENT_TIMESTAMP,
                    user_count = user_count + 1 WHERE id = ?
            ''', (existing['id'],))
            conn.commit()
            # Re-fetch to get the updated user_count
            updated = conn.execute(
                'SELECT * FROM campaigns WHERE id = ?', (existing['id'],)
            ).fetchone()
            return dict(updated), False

        # Create new campaign
        campaign_id = str(uuid.uuid4())
        name = f"{sender_domain} - {subject[:50]}"
        indicators = json.dumps({
            'sender_domain': sender_domain,
            'subject_pattern': subject
        })
        conn.execute('''
            INSERT INTO campaigns (id, name, fingerprint, first_seen, last_seen,
                user_count, status, indicators)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, 'active', ?)
        ''', (campaign_id, name, fingerprint, indicators))
        conn.commit()

        campaign = conn.execute('SELECT * FROM campaigns WHERE id = ?', (campaign_id,)).fetchone()
        return dict(campaign), True


def get_active_campaigns():
    with get_db() as conn:
        rows = conn.execute('''
            SELECT * FROM campaigns WHERE status = 'active'
            ORDER BY user_count DESC
        ''').fetchall()
        return [dict(row) for row in rows]


def get_campaign_alert_level(campaign_id):
    from config import CAMPAIGN_WARNING, CAMPAIGN_ELEVATED, CAMPAIGN_CRITICAL
    with get_db() as conn:
        row = conn.execute('''
            SELECT
                SUM(CASE WHEN submitted_at >= datetime('now', '-1 hour') THEN 1 ELSE 0 END) as count_1h,
                SUM(CASE WHEN submitted_at >= datetime('now', '-2 hours') THEN 1 ELSE 0 END) as count_2h,
                SUM(CASE WHEN submitted_at >= datetime('now', '-4 hours') THEN 1 ELSE 0 END) as count_4h
            FROM submissions
            WHERE campaign_id = ? AND submitted_at >= datetime('now', '-4 hours')
        ''', (campaign_id,)).fetchone()

        count_1h = row['count_1h'] or 0
        count_2h = row['count_2h'] or 0
        count_4h = row['count_4h'] or 0

        if count_4h >= CAMPAIGN_CRITICAL:
            return 'critical'
        elif count_2h >= CAMPAIGN_ELEVATED:
            return 'elevated'
        elif count_1h >= CAMPAIGN_WARNING:
            return 'warning'
        return 'normal'


# Feedback functions
def create_feedback(submission_id, user_email, original_verdict, user_says, reason=None, notes=None):
    feedback_id = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute('''
            INSERT INTO feedback (id, submission_id, user_email, original_verdict,
                user_says, reason, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (feedback_id, submission_id, user_email, original_verdict, user_says, reason, notes))
        conn.commit()
    return feedback_id


def get_feedback_stats(days=30):
    with get_db() as conn:
        stats = {}

        # Total feedback
        stats['total'] = conn.execute('''
            SELECT COUNT(*) FROM feedback
            WHERE submitted_at >= datetime('now', ?)
        ''', (f'-{days} days',)).fetchone()[0]

        # By verdict accuracy
        for verdict in ['phishing', 'suspicious', 'safe']:
            correct = conn.execute('''
                SELECT COUNT(*) FROM feedback
                WHERE original_verdict = ? AND user_says = 'correct'
                AND submitted_at >= datetime('now', ?)
            ''', (verdict, f'-{days} days')).fetchone()[0]

            total = conn.execute('''
                SELECT COUNT(*) FROM feedback
                WHERE original_verdict = ?
                AND submitted_at >= datetime('now', ?)
            ''', (verdict, f'-{days} days')).fetchone()[0]

            stats[f'{verdict}_accuracy'] = (correct / total * 100) if total > 0 else 0
            stats[f'{verdict}_total'] = total
            stats[f'{verdict}_correct'] = correct

        # Pending reviews
        stats['pending'] = conn.execute('''
            SELECT COUNT(*) FROM feedback WHERE review_status = 'pending'
        ''').fetchone()[0]

        return stats


def get_pending_feedback():
    with get_db() as conn:
        rows = conn.execute('''
            SELECT f.*, s.subject, s.original_sender, s.confidence
            FROM feedback f
            JOIN submissions s ON f.submission_id = s.id
            WHERE f.review_status = 'pending'
            ORDER BY f.submitted_at DESC
        ''').fetchall()
        return [dict(row) for row in rows]


# Whitelist/Blacklist functions
def add_to_whitelist(type_, value, reason, added_by):
    entry_id = str(uuid.uuid4())
    value_lower = value.lower()
    with get_db() as conn:
        # Check for existing duplicate
        existing = conn.execute(
            'SELECT id FROM whitelist WHERE type = ? AND value = ?',
            (type_, value_lower)
        ).fetchone()
        if existing:
            return existing['id']
        conn.execute('''
            INSERT INTO whitelist (id, type, value, reason, added_by)
            VALUES (?, ?, ?, ?, ?)
        ''', (entry_id, type_, value_lower, reason, added_by))
        conn.commit()
    return entry_id


def is_whitelisted(sender, domain):
    with get_db() as conn:
        # Check sender
        sender_match = conn.execute('''
            SELECT 1 FROM whitelist WHERE type = 'sender' AND value = ?
        ''', ((sender or '').lower(),)).fetchone()
        if sender_match:
            return True

        # Check domain
        domain_match = conn.execute('''
            SELECT 1 FROM whitelist WHERE type = 'domain' AND value = ?
        ''', ((domain or '').lower(),)).fetchone()
        return domain_match is not None


def add_to_blacklist(type_, value, reason, added_by):
    entry_id = str(uuid.uuid4())
    value_lower = value.lower()
    with get_db() as conn:
        # Check for existing duplicate
        existing = conn.execute(
            'SELECT id FROM blacklist WHERE type = ? AND value = ?',
            (type_, value_lower)
        ).fetchone()
        if existing:
            return existing['id']
        conn.execute('''
            INSERT INTO blacklist (id, type, value, reason, added_by)
            VALUES (?, ?, ?, ?, ?)
        ''', (entry_id, type_, value_lower, reason, added_by))
        conn.commit()
    return entry_id


def is_blacklisted(sender, domain):
    with get_db() as conn:
        # Check sender
        sender_match = conn.execute('''
            SELECT 1 FROM blacklist WHERE type = 'sender' AND value = ?
        ''', ((sender or '').lower(),)).fetchone()
        if sender_match:
            return True

        # Check domain
        domain_match = conn.execute('''
            SELECT 1 FROM blacklist WHERE type = 'domain' AND value = ?
        ''', ((domain or '').lower(),)).fetchone()
        return domain_match is not None


def get_whitelist():
    with get_db() as conn:
        rows = conn.execute('SELECT * FROM whitelist ORDER BY added_at DESC').fetchall()
        return [dict(row) for row in rows]


def get_blacklist():
    with get_db() as conn:
        rows = conn.execute('SELECT * FROM blacklist ORDER BY added_at DESC').fetchall()
        return [dict(row) for row in rows]


def remove_from_whitelist(entry_id):
    with get_db() as conn:
        conn.execute('DELETE FROM whitelist WHERE id = ?', (entry_id,))
        conn.commit()


def remove_from_blacklist(entry_id):
    with get_db() as conn:
        conn.execute('DELETE FROM blacklist WHERE id = ?', (entry_id,))
        conn.commit()


# Unique users count
def get_unique_users(days=30):
    with get_db() as conn:
        count = conn.execute('''
            SELECT COUNT(DISTINCT submitted_by) FROM submissions
            WHERE submitted_at >= datetime('now', ?)
        ''', (f'-{days} days',)).fetchone()[0]
        return count


# Auto-learning functions
def check_auto_whitelist(domain, threshold=None):
    """
    Check if a domain should be auto-whitelisted based on repeated false positives.
    Returns True if domain was auto-whitelisted.
    """
    if not domain:
        return False

    if threshold is None:
        from config import AUTO_WHITELIST_THRESHOLD
        threshold = AUTO_WHITELIST_THRESHOLD

    domain = domain.lower()

    with get_db() as conn:
        # Check if already whitelisted
        existing = conn.execute(
            'SELECT 1 FROM whitelist WHERE type = ? AND value = ?',
            ('domain', domain)
        ).fetchone()
        if existing:
            return False

        # Count SOC-reviewed false positives for this domain
        # Only confirmed reviews count — unreviewed feedback cannot trigger auto-whitelist
        fp_count = conn.execute('''
            SELECT COUNT(DISTINCT f.id) FROM feedback f
            JOIN submissions s ON f.submission_id = s.id
            WHERE s.sender_domain = ?
            AND f.user_says = 'false_positive'
            AND f.original_verdict IN ('phishing', 'suspicious')
            AND f.review_status = 'confirmed'
        ''', (domain,)).fetchone()[0]

        if fp_count >= threshold:
            # Auto-whitelist this domain
            add_to_whitelist(
                'domain',
                domain,
                f'Auto-whitelisted after {fp_count} confirmed false positives',
                'system-auto'
            )
            return True

    return False


def get_auto_whitelist_candidates(threshold=2):
    """
    Get domains that are close to being auto-whitelisted.
    Returns list of (domain, fp_count) tuples.
    """
    with get_db() as conn:
        rows = conn.execute('''
            SELECT s.sender_domain, COUNT(DISTINCT f.id) as fp_count
            FROM feedback f
            JOIN submissions s ON f.submission_id = s.id
            WHERE f.user_says = 'false_positive'
            AND f.original_verdict IN ('phishing', 'suspicious')
            AND s.sender_domain IS NOT NULL
            AND s.sender_domain NOT IN (SELECT value FROM whitelist WHERE type = 'domain')
            GROUP BY s.sender_domain
            HAVING fp_count >= ?
            ORDER BY fp_count DESC
        ''', (threshold,)).fetchall()
        return [(row['sender_domain'], row['fp_count']) for row in rows]


def get_learning_stats():
    """Get statistics about the learning system."""
    with get_db() as conn:
        stats = {}

        # Auto-whitelisted count
        stats['auto_whitelisted'] = conn.execute('''
            SELECT COUNT(*) FROM whitelist WHERE added_by = 'system-auto'
        ''').fetchone()[0]

        # Manual whitelist count
        stats['manual_whitelisted'] = conn.execute('''
            SELECT COUNT(*) FROM whitelist WHERE added_by != 'system-auto'
        ''').fetchone()[0]

        # Candidates for auto-whitelist
        candidates = get_auto_whitelist_candidates(2)
        stats['candidates'] = candidates[:10]  # Top 10

        # Total feedback received
        stats['total_feedback'] = conn.execute('''
            SELECT COUNT(*) FROM feedback
        ''').fetchone()[0]

        # False positive rate
        total_fp = conn.execute('''
            SELECT COUNT(*) FROM feedback WHERE user_says = 'false_positive'
        ''').fetchone()[0]

        stats['false_positive_count'] = total_fp
        stats['false_positive_rate'] = (total_fp / stats['total_feedback'] * 100) if stats['total_feedback'] > 0 else 0

        return stats
