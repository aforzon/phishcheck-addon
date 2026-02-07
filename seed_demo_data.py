"""
Demo Data Seeder

Generates realistic fake phishing emails for CISO demo.
Run this to populate the database with sample data.

Usage: python seed_demo_data.py
"""

import random
from datetime import datetime, timedelta
import uuid
import json
from models import init_db, get_db

# Initialize database
init_db()

# Sample phishing campaigns
PHISHING_CAMPAIGNS = [
    {
        'sender_domain': 'micros0ft-verify.xyz',
        'subject_templates': [
            'Urgent: Verify your Microsoft 365 account',
            'Action Required: Your Microsoft account will be suspended',
            'Microsoft Security Alert: Unusual sign-in activity',
        ],
        'verdict': 'phishing',
        'confidence': 87,
        'signals': [
            {'name': 'microsoft_phishing', 'description': 'Microsoft flagged this as phishing', 'weight': 40},
            {'name': 'lookalike_domain', 'description': 'Sender domain appears to impersonate Microsoft', 'weight': 15},
            {'name': 'suspicious_tld', 'description': 'Sender uses suspicious TLD (.xyz)', 'weight': 10},
            {'name': 'urgency_language', 'description': 'Email uses urgency language to pressure quick action', 'weight': 5},
        ]
    },
    {
        'sender_domain': 'paypa1-secure.com',
        'subject_templates': [
            'Your PayPal account has been limited',
            'PayPal: Confirm your identity to restore access',
            'Important: Unusual activity on your PayPal account',
        ],
        'verdict': 'phishing',
        'confidence': 92,
        'signals': [
            {'name': 'spf_fail', 'description': 'SPF authentication failed - sender IP not authorized', 'weight': 15},
            {'name': 'dkim_fail', 'description': 'DKIM signature verification failed', 'weight': 15},
            {'name': 'lookalike_domain', 'description': 'Sender domain appears to impersonate PayPal', 'weight': 15},
            {'name': 'credential_request', 'description': 'Email requests credential or identity verification', 'weight': 5},
            {'name': 'suspicious_link', 'description': 'Email contains suspicious link', 'weight': 10},
        ]
    },
    {
        'sender_domain': 'docusign-notify.tk',
        'subject_templates': [
            'Document ready for signature',
            'DocuSign: Please review and sign',
            'Completed: Agreement sent for your signature',
        ],
        'verdict': 'phishing',
        'confidence': 78,
        'signals': [
            {'name': 'suspicious_tld', 'description': 'Sender uses suspicious TLD (.tk)', 'weight': 10},
            {'name': 'lookalike_domain', 'description': 'Sender domain appears to impersonate DocuSign', 'weight': 15},
            {'name': 'suspicious_link', 'description': 'Email contains suspicious link', 'weight': 10},
        ]
    },
    {
        'sender_domain': 'voicemail-notification.info',
        'subject_templates': [
            'You have a new voicemail from +1-555-0123',
            'Missed call: Voicemail message waiting',
            'New voicemail: 00:47 duration',
        ],
        'verdict': 'phishing',
        'confidence': 71,
        'signals': [
            {'name': 'domain_age_30', 'description': 'Domain has suspicious registration pattern', 'weight': 10},
            {'name': 'suspicious_tld', 'description': 'Sender uses suspicious TLD (.info)', 'weight': 10},
            {'name': 'generic_greeting', 'description': 'Email uses generic greeting instead of your name', 'weight': 5},
        ]
    },
]

# Suspicious emails (lower confidence)
SUSPICIOUS_EMAILS = [
    {
        'sender': 'billing@vendor-invoices.net',
        'sender_domain': 'vendor-invoices.net',
        'subject': 'Invoice #INV-2024-0892 attached',
        'verdict': 'suspicious',
        'confidence': 52,
        'signals': [
            {'name': 'domain_age_30', 'description': 'Domain has suspicious registration pattern', 'weight': 10},
            {'name': 'generic_greeting', 'description': 'Email uses generic greeting instead of your name', 'weight': 5},
        ]
    },
    {
        'sender': 'hr@benefits-update.com',
        'sender_domain': 'benefits-update.com',
        'subject': 'Important: Open enrollment deadline approaching',
        'verdict': 'suspicious',
        'confidence': 45,
        'signals': [
            {'name': 'urgency_language', 'description': 'Email uses urgency language to pressure quick action', 'weight': 5},
            {'name': 'domain_age_30', 'description': 'Domain has suspicious registration pattern', 'weight': 10},
        ]
    },
]

# Safe emails
SAFE_EMAILS = [
    {
        'sender': 'noreply@microsoft.com',
        'sender_domain': 'microsoft.com',
        'subject': 'Your Microsoft 365 subscription renewal',
        'verdict': 'safe',
        'confidence': 12,
        'signals': []
    },
    {
        'sender': 'notifications@linkedin.com',
        'sender_domain': 'linkedin.com',
        'subject': 'John Smith viewed your profile',
        'verdict': 'safe',
        'confidence': 8,
        'signals': []
    },
    {
        'sender': 'support@zoom.us',
        'sender_domain': 'zoom.us',
        'subject': 'Your meeting recording is ready',
        'verdict': 'safe',
        'confidence': 5,
        'signals': []
    },
]

# Departments
DEPARTMENTS = ['Finance', 'HR', 'Engineering', 'Sales', 'Marketing', 'Executive', 'IT', 'Legal', 'Operations']

# Sample users
def generate_user():
    first_names = ['John', 'Jane', 'Michael', 'Sarah', 'David', 'Emily', 'Robert', 'Lisa', 'James', 'Jennifer']
    last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez']
    first = random.choice(first_names)
    last = random.choice(last_names)
    return f'{first.lower()}.{last.lower()}@forzon.ca'


def seed_campaigns():
    """Create campaign entries and submissions."""
    print("Seeding campaigns and phishing submissions...")

    with get_db() as conn:
        for campaign_data in PHISHING_CAMPAIGNS:
            # Create campaign
            campaign_id = str(uuid.uuid4())
            fingerprint = str(uuid.uuid4())[:32]

            # Randomize timing
            first_seen = datetime.now() - timedelta(hours=random.randint(1, 48))
            last_seen = datetime.now() - timedelta(minutes=random.randint(5, 120))
            user_count = random.randint(15, 85)

            indicators = json.dumps({
                'sender_domain': campaign_data['sender_domain'],
                'subject_pattern': campaign_data['subject_templates'][0]
            })

            conn.execute('''
                INSERT INTO campaigns (id, name, fingerprint, first_seen, last_seen, user_count, status, indicators)
                VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
            ''', (
                campaign_id,
                f"{campaign_data['sender_domain']} - {campaign_data['subject_templates'][0][:30]}",
                fingerprint,
                first_seen.isoformat(),
                last_seen.isoformat(),
                user_count,
                indicators
            ))

            # Create submissions for this campaign
            for i in range(user_count):
                submission_id = str(uuid.uuid4())
                submitted_at = first_seen + timedelta(minutes=random.randint(0, int((last_seen - first_seen).total_seconds() / 60)))
                subject = random.choice(campaign_data['subject_templates'])
                department = random.choice(DEPARTMENTS)

                # Weight certain departments more heavily for realism
                if random.random() < 0.3:
                    department = 'Finance'
                elif random.random() < 0.2:
                    department = 'HR'

                conn.execute('''
                    INSERT INTO submissions (id, fingerprint, submitted_at, submitted_by, submission_method,
                        department, original_sender, sender_domain, subject, verdict, confidence, signals, campaign_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    submission_id,
                    fingerprint,
                    submitted_at.isoformat(),
                    generate_user(),
                    random.choice(['addon', 'forward']),
                    department,
                    f'security@{campaign_data["sender_domain"]}',
                    campaign_data['sender_domain'],
                    subject,
                    campaign_data['verdict'],
                    campaign_data['confidence'],
                    json.dumps(campaign_data['signals']),
                    campaign_id
                ))

        conn.commit()


def seed_other_emails():
    """Seed suspicious and safe emails."""
    print("Seeding suspicious and safe emails...")

    with get_db() as conn:
        # Suspicious emails
        for email_data in SUSPICIOUS_EMAILS:
            for _ in range(random.randint(5, 15)):
                submission_id = str(uuid.uuid4())
                submitted_at = datetime.now() - timedelta(hours=random.randint(1, 168))

                conn.execute('''
                    INSERT INTO submissions (id, fingerprint, submitted_at, submitted_by, submission_method,
                        department, original_sender, sender_domain, subject, verdict, confidence, signals)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    submission_id,
                    str(uuid.uuid4())[:32],
                    submitted_at.isoformat(),
                    generate_user(),
                    random.choice(['addon', 'forward']),
                    random.choice(DEPARTMENTS),
                    email_data['sender'],
                    email_data['sender_domain'],
                    email_data['subject'],
                    email_data['verdict'],
                    email_data['confidence'],
                    json.dumps(email_data['signals'])
                ))

        # Safe emails
        for email_data in SAFE_EMAILS:
            for _ in range(random.randint(20, 50)):
                submission_id = str(uuid.uuid4())
                submitted_at = datetime.now() - timedelta(hours=random.randint(1, 168))

                conn.execute('''
                    INSERT INTO submissions (id, fingerprint, submitted_at, submitted_by, submission_method,
                        department, original_sender, sender_domain, subject, verdict, confidence, signals)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    submission_id,
                    str(uuid.uuid4())[:32],
                    submitted_at.isoformat(),
                    generate_user(),
                    random.choice(['addon', 'forward']),
                    random.choice(DEPARTMENTS),
                    email_data['sender'],
                    email_data['sender_domain'],
                    email_data['subject'],
                    email_data['verdict'],
                    email_data['confidence'],
                    json.dumps(email_data['signals'])
                ))

        conn.commit()


def seed_feedback():
    """Seed some user feedback."""
    print("Seeding user feedback...")

    with get_db() as conn:
        # Get some submissions to add feedback
        submissions = conn.execute('''
            SELECT id, verdict FROM submissions ORDER BY RANDOM() LIMIT 50
        ''').fetchall()

        for sub in submissions:
            # 85% correct feedback, 15% disputed
            if random.random() < 0.85:
                user_says = 'correct'
            else:
                user_says = 'false_positive' if sub['verdict'] == 'phishing' else 'false_negative'

            feedback_id = str(uuid.uuid4())
            conn.execute('''
                INSERT INTO feedback (id, submission_id, user_email, original_verdict, user_says, submitted_at, review_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                feedback_id,
                sub['id'],
                generate_user(),
                sub['verdict'],
                user_says,
                (datetime.now() - timedelta(hours=random.randint(1, 48))).isoformat(),
                'pending' if user_says != 'correct' else 'confirmed'
            ))

        conn.commit()


def seed_whitelist_blacklist():
    """Seed some whitelist and blacklist entries."""
    print("Seeding whitelist and blacklist...")

    with get_db() as conn:
        # Whitelist
        whitelist_entries = [
            ('domain', 'microsoft.com', 'Verified Microsoft domain'),
            ('domain', 'google.com', 'Verified Google domain'),
            ('domain', 'zoom.us', 'Verified Zoom domain'),
            ('sender', 'ceo@forzon.ca', 'Internal executive'),
        ]
        for type_, value, reason in whitelist_entries:
            conn.execute('''
                INSERT INTO whitelist (id, type, value, reason, added_by)
                VALUES (?, ?, ?, ?, 'admin')
            ''', (str(uuid.uuid4()), type_, value, reason))

        # Blacklist
        blacklist_entries = [
            ('domain', 'paypa1-secure.com', 'Known phishing domain'),
            ('domain', 'micros0ft-verify.xyz', 'Known phishing domain'),
        ]
        for type_, value, reason in blacklist_entries:
            conn.execute('''
                INSERT INTO blacklist (id, type, value, reason, added_by)
                VALUES (?, ?, ?, ?, 'admin')
            ''', (str(uuid.uuid4()), type_, value, reason))

        conn.commit()


def main():
    print("=" * 50)
    print("PhishCheck Demo Data Seeder")
    print("=" * 50)

    # Clear existing data
    print("\nClearing existing data...")
    with get_db() as conn:
        conn.execute('DELETE FROM feedback')
        conn.execute('DELETE FROM submissions')
        conn.execute('DELETE FROM campaigns')
        conn.execute('DELETE FROM whitelist')
        conn.execute('DELETE FROM blacklist')
        conn.commit()

    # Seed data
    seed_campaigns()
    seed_other_emails()
    seed_feedback()
    seed_whitelist_blacklist()

    # Print summary
    with get_db() as conn:
        campaigns = conn.execute('SELECT COUNT(*) FROM campaigns').fetchone()[0]
        submissions = conn.execute('SELECT COUNT(*) FROM submissions').fetchone()[0]
        phishing = conn.execute('SELECT COUNT(*) FROM submissions WHERE verdict = "phishing"').fetchone()[0]
        feedback = conn.execute('SELECT COUNT(*) FROM feedback').fetchone()[0]

    print("\n" + "=" * 50)
    print("Demo data seeded successfully!")
    print("=" * 50)
    print(f"  Campaigns: {campaigns}")
    print(f"  Submissions: {submissions}")
    print(f"  Phishing detected: {phishing}")
    print(f"  Feedback entries: {feedback}")
    print("\nYou can now start the app and login with:")
    print("  Username: admin")
    print("  Password: phishcheck2024")


if __name__ == '__main__':
    main()
