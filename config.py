import os
from dotenv import load_dotenv

load_dotenv()

# Flask
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'

# Database
DATABASE_PATH = os.getenv('DATABASE_PATH', 'phishcheck.db')

# Microsoft Graph API
AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID', '')
AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID', '')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET', '')
PHISHING_MAILBOX = os.getenv('PHISHING_MAILBOX', 'phishing@forzon.ca')

# Email Configuration (Purelymail)
IMAP_HOST = os.getenv('IMAP_HOST', 'imap.purelymail.com')
IMAP_PORT = int(os.getenv('IMAP_PORT', '993'))
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.purelymail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
EMAIL_USER = os.getenv('EMAIL_USER', 'phishing@forzon.ca')
EMAIL_PASS = os.getenv('EMAIL_PASS', '')

# Graph API endpoints
GRAPH_API_BASE = 'https://graph.microsoft.com/v1.0'
GRAPH_SCOPE = ['https://graph.microsoft.com/.default']

# Analysis thresholds
THRESHOLD_PHISHING = int(os.getenv('THRESHOLD_PHISHING', '70'))
THRESHOLD_SUSPICIOUS = int(os.getenv('THRESHOLD_SUSPICIOUS', '40'))

# Signal weights (tunable)
WEIGHTS = {
    'microsoft_phishing': 40,
    'spf_fail': 15,
    'dkim_fail': 15,
    'dmarc_fail': 10,
    'high_scl': 10,
    'high_pcl': 15,
    'domain_age_7': 15,
    'domain_age_30': 10,
    'reply_to_mismatch': 10,
    'lookalike_domain': 15,
    'suspicious_tld': 10,
    'urgency_language': 5,
    'credential_request': 5,
    'generic_greeting': 5,
    'suspicious_link': 10,
    'blacklist': 30,
    'whitelist': -40,
    # Forwarded email detection
    'suspicious_sender_pattern': 15,
    'display_name_mismatch': 10,
    'freemail_random': 10,
    # Additional signals
    'image_only_email': 15,
    'clickable_image': 10,
    'vague_subject': 5,
    'hidden_text': 10,
    'display_email_mismatch': 10,
    # URL detonation signals
    'url_high_risk': 30,
    'url_medium_risk': 15,
    'url_malicious': 40,
    # Additional checks
    'mismatched_link': 20,
    'suspicious_attachment': 20,
    'financial_keywords': 10,
    'excessive_links': 10,
    'homograph_attack': 25,
    # DNS checks
    'no_mx_record': 15,
    'no_spf_record': 10,
    'no_dmarc_record': 5,
}

# Suspicious TLDs
SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.work', '.click', '.link', '.info', '.online', '.site',
    '.club', '.buzz', '.icu', '.cam', '.rest', '.monster'
]

# Campaign detection thresholds
CAMPAIGN_WARNING = 10      # users in 1 hour
CAMPAIGN_ELEVATED = 30     # users in 2 hours
CAMPAIGN_CRITICAL = 60     # users in 4 hours

# CISO Alert settings
CISO_EMAIL = os.getenv('CISO_EMAIL', '')  # e.g., 'ciso@forzon.ca'
ENABLE_CISO_ALERTS = os.getenv('ENABLE_CISO_ALERTS', 'True').lower() == 'true'

# Demo credentials (for development only)
DEMO_USERNAME = os.getenv('DEMO_USERNAME', 'admin')
DEMO_PASSWORD = os.getenv('DEMO_PASSWORD', 'phishcheck2024')

# URL Detonation (urlscan.io)
URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY', '')
ENABLE_URL_DETONATION = os.getenv('ENABLE_URL_DETONATION', 'True').lower() == 'true'
DETONATION_OUTPUT_DIR = os.getenv('DETONATION_OUTPUT_DIR', './detonations')

# Auto-learning settings
AUTO_WHITELIST_THRESHOLD = int(os.getenv('AUTO_WHITELIST_THRESHOLD', '3'))  # FPs needed to auto-whitelist
