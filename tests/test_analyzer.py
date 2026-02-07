"""Tests for the email analysis engine."""

import pytest
from unittest.mock import patch

# Test data
PHISHING_HEADERS_O365 = """\
From: security@paypa1.xyz <security@paypa1.xyz>
To: user@forzon.ca
Subject: Urgent: Verify your account
Authentication-Results: spf=fail; dkim=fail; dmarc=fail
X-Forefront-Antispam-Report: CAT:PHSH;SCL:9;PCL:6
X-MS-Exchange-Organization-SCL: 9
Reply-To: different@evil.com
"""

SAFE_HEADERS = """\
From: noreply@microsoft.com
To: user@forzon.ca
Subject: Your monthly report
Authentication-Results: spf=pass; dkim=pass; dmarc=pass
X-Forefront-Antispam-Report: CAT:NONE;SCL:1;PCL:0
"""

PHISHING_BODY = """
<html>
<body>
<p>Dear Customer,</p>
<p>Your account has been suspended. Click immediately to verify your identity.</p>
<p><a href="http://paypa1.xyz/verify">https://www.paypal.com/verify</a></p>
<p>This is urgent - your account expires in 24 hours!</p>
</body>
</html>
"""

SAFE_BODY = """
<html>
<body>
<p>Hi John,</p>
<p>Here is your monthly usage report for January 2026.</p>
<p><a href="https://microsoft.com/reports">View Report</a></p>
</body>
</html>
"""


# ═══════════════════════════════════════════════════════════════════════════════
# Domain Extraction
# ═══════════════════════════════════════════════════════════════════════════════

class TestDomainExtraction:
    def test_simple_email(self, analyzer_instance):
        assert analyzer_instance._extract_domain('user@example.com') == 'example.com'

    def test_email_with_display_name(self, analyzer_instance):
        assert analyzer_instance._extract_domain('"John" <john@example.com>') == 'example.com'

    def test_empty_email(self, analyzer_instance):
        assert analyzer_instance._extract_domain('') == ''

    def test_none_email(self, analyzer_instance):
        assert analyzer_instance._extract_domain(None) == ''

    def test_no_at_sign(self, analyzer_instance):
        assert analyzer_instance._extract_domain('not-an-email') == ''

    def test_uppercase_domain(self, analyzer_instance):
        assert analyzer_instance._extract_domain('user@EXAMPLE.COM') == 'example.com'


# ═══════════════════════════════════════════════════════════════════════════════
# O365 Header Parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestO365HeaderParsing:
    def test_spf_fail_detected(self, analyzer_instance):
        headers = "Authentication-Results: spf=fail; dkim=pass"
        signals = analyzer_instance._parse_o365_headers(headers)
        names = [s['name'] for s in signals]
        assert 'spf_fail' in names

    def test_spf_softfail_detected(self, analyzer_instance):
        headers = "Authentication-Results: spf=softfail; dkim=pass"
        signals = analyzer_instance._parse_o365_headers(headers)
        names = [s['name'] for s in signals]
        assert 'spf_fail' in names

    def test_spf_pass_no_signal(self, analyzer_instance):
        headers = "Authentication-Results: spf=pass; dkim=pass"
        signals = analyzer_instance._parse_o365_headers(headers)
        names = [s['name'] for s in signals]
        assert 'spf_fail' not in names

    def test_dkim_fail_detected(self, analyzer_instance):
        headers = "Authentication-Results: spf=pass; dkim=fail"
        signals = analyzer_instance._parse_o365_headers(headers)
        names = [s['name'] for s in signals]
        assert 'dkim_fail' in names

    def test_dmarc_fail_detected(self, analyzer_instance):
        headers = "Authentication-Results: dmarc=fail"
        signals = analyzer_instance._parse_o365_headers(headers)
        names = [s['name'] for s in signals]
        assert 'dmarc_fail' in names

    def test_microsoft_phishing_category(self, analyzer_instance):
        headers = "X-Forefront-Antispam-Report: CAT:PHSH;SCL:5"
        signals = analyzer_instance._parse_o365_headers(headers)
        names = [s['name'] for s in signals]
        assert 'microsoft_phishing' in names

    def test_high_scl(self, analyzer_instance):
        headers = "X-Forefront-Antispam-Report: CAT:NONE;SCL:8"
        signals = analyzer_instance._parse_o365_headers(headers)
        names = [s['name'] for s in signals]
        assert 'high_scl' in names

    def test_low_scl_no_signal(self, analyzer_instance):
        headers = "X-Forefront-Antispam-Report: CAT:NONE;SCL:3"
        signals = analyzer_instance._parse_o365_headers(headers)
        names = [s['name'] for s in signals]
        assert 'high_scl' not in names

    def test_high_pcl(self, analyzer_instance):
        headers = "X-Forefront-Antispam-Report: CAT:NONE;SCL:1;PCL:6"
        signals = analyzer_instance._parse_o365_headers(headers)
        names = [s['name'] for s in signals]
        assert 'high_pcl' in names

    def test_org_scl_header(self, analyzer_instance):
        headers = "X-MS-Exchange-Organization-SCL: 9"
        signals = analyzer_instance._parse_o365_headers(headers)
        names = [s['name'] for s in signals]
        assert 'high_scl' in names

    def test_no_duplicate_scl(self, analyzer_instance):
        """SCL from antispam report should not duplicate with org SCL header."""
        headers = "X-Forefront-Antispam-Report: SCL:8\nX-MS-Exchange-Organization-SCL: 8"
        signals = analyzer_instance._parse_o365_headers(headers)
        scl_count = sum(1 for s in signals if s['name'] == 'high_scl')
        assert scl_count == 1

    def test_empty_headers(self, analyzer_instance):
        assert analyzer_instance._parse_o365_headers('') == []

    def test_none_headers(self, analyzer_instance):
        assert analyzer_instance._parse_o365_headers(None) == []

    def test_all_signals_from_phishing_headers(self, analyzer_instance):
        signals = analyzer_instance._parse_o365_headers(PHISHING_HEADERS_O365)
        names = [s['name'] for s in signals]
        assert 'spf_fail' in names
        assert 'dkim_fail' in names
        assert 'dmarc_fail' in names
        assert 'microsoft_phishing' in names
        assert 'high_scl' in names
        assert 'high_pcl' in names


# ═══════════════════════════════════════════════════════════════════════════════
# Header Finding
# ═══════════════════════════════════════════════════════════════════════════════

class TestFindHeader:
    def test_simple_header(self, analyzer_instance):
        headers = "From: user@example.com\nTo: other@example.com"
        assert analyzer_instance._find_header(headers, 'From') == 'user@example.com'

    def test_case_insensitive(self, analyzer_instance):
        headers = "from: user@example.com"
        assert analyzer_instance._find_header(headers, 'From') == 'user@example.com'

    def test_folded_header(self, analyzer_instance):
        headers = "Authentication-Results: spf=pass;\n    dkim=pass;\n    dmarc=pass"
        result = analyzer_instance._find_header(headers, 'Authentication-Results')
        assert 'spf=pass' in result
        assert 'dkim=pass' in result
        assert 'dmarc=pass' in result

    def test_missing_header(self, analyzer_instance):
        headers = "From: user@example.com"
        assert analyzer_instance._find_header(headers, 'Reply-To') is None


# ═══════════════════════════════════════════════════════════════════════════════
# Lookalike Domain Detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestLookalikeDomain:
    def test_paypal_with_number(self, analyzer_instance):
        assert analyzer_instance._is_lookalike_domain('paypa1.com') is True

    def test_microsoft_with_zero(self, analyzer_instance):
        assert analyzer_instance._is_lookalike_domain('micr0soft.com') is True

    def test_brand_with_suffix(self, analyzer_instance):
        assert analyzer_instance._is_lookalike_domain('paypal-secure.com') is True

    def test_brand_with_prefix(self, analyzer_instance):
        assert analyzer_instance._is_lookalike_domain('my-amazon.com') is True

    def test_legitimate_domain(self, analyzer_instance):
        assert analyzer_instance._is_lookalike_domain('example.com') is False

    def test_actual_brand(self, analyzer_instance):
        """The actual brand domain should NOT be flagged."""
        assert analyzer_instance._is_lookalike_domain('microsoft.com') is False
        assert analyzer_instance._is_lookalike_domain('paypal.com') is False

    def test_rn_to_m_substitution(self, analyzer_instance):
        assert analyzer_instance._is_lookalike_domain('rnicrosoft.com') is True


# ═══════════════════════════════════════════════════════════════════════════════
# Suspicious TLD
# ═══════════════════════════════════════════════════════════════════════════════

class TestSuspiciousTLD:
    def test_xyz_tld(self, analyzer_instance):
        signals = analyzer_instance._internal_checks('user@evil.xyz', 'evil.xyz', 'Test', '', '')
        names = [s['name'] for s in signals]
        assert 'suspicious_tld' in names

    def test_tk_tld(self, analyzer_instance):
        signals = analyzer_instance._internal_checks('user@evil.tk', 'evil.tk', 'Test', '', '')
        names = [s['name'] for s in signals]
        assert 'suspicious_tld' in names

    def test_com_tld_not_flagged(self, analyzer_instance):
        signals = analyzer_instance._internal_checks('user@example.com', 'example.com', 'Test', '', '')
        names = [s['name'] for s in signals]
        assert 'suspicious_tld' not in names


# ═══════════════════════════════════════════════════════════════════════════════
# Reply-To Mismatch
# ═══════════════════════════════════════════════════════════════════════════════

class TestReplyToMismatch:
    def test_mismatched_reply_to(self, analyzer_instance):
        headers = "Reply-To: attacker@evil.com"
        signals = analyzer_instance._internal_checks(
            'user@company.com', 'company.com', 'Test', '', headers
        )
        names = [s['name'] for s in signals]
        assert 'reply_to_mismatch' in names

    def test_matching_reply_to(self, analyzer_instance):
        headers = "Reply-To: other@company.com"
        signals = analyzer_instance._internal_checks(
            'user@company.com', 'company.com', 'Test', '', headers
        )
        names = [s['name'] for s in signals]
        assert 'reply_to_mismatch' not in names


# ═══════════════════════════════════════════════════════════════════════════════
# Content Analysis
# ═══════════════════════════════════════════════════════════════════════════════

class TestContentAnalysis:
    def test_urgency_language(self, analyzer_instance):
        body = "<p>Act now! Your account expires immediately!</p>"
        signals = analyzer_instance._analyze_content(body, '')
        names = [s['name'] for s in signals]
        assert 'urgency_language' in names

    def test_credential_request(self, analyzer_instance):
        body = "<p>Please verify your password and account information.</p>"
        signals = analyzer_instance._analyze_content(body, '')
        names = [s['name'] for s in signals]
        assert 'credential_request' in names

    def test_generic_greeting(self, analyzer_instance):
        body = "<p>Dear Customer,</p><p>Your account needs attention.</p>"
        signals = analyzer_instance._analyze_content(body, '')
        names = [s['name'] for s in signals]
        assert 'generic_greeting' in names

    def test_normal_content_no_signals(self, analyzer_instance):
        body = "<p>Hi John, here is the report you requested. Best regards, Sarah.</p>"
        signals = analyzer_instance._analyze_content(body, '')
        assert len(signals) == 0

    def test_urgency_in_subject(self, analyzer_instance):
        signals = analyzer_instance._analyze_content('<p>See details.</p>', 'URGENT: Action required')
        names = [s['name'] for s in signals]
        assert 'urgency_language' in names


# ═══════════════════════════════════════════════════════════════════════════════
# Link Analysis
# ═══════════════════════════════════════════════════════════════════════════════

class TestLinkAnalysis:
    def test_ip_address_url(self, analyzer_instance):
        body = '<a href="http://192.168.1.1/login">Click here</a>'
        signals = analyzer_instance._analyze_links(body)
        names = [s['name'] for s in signals]
        assert 'suspicious_link' in names

    def test_url_shortener(self, analyzer_instance):
        body = '<a href="http://bit.ly/abc123">Click here</a>'
        signals = analyzer_instance._analyze_links(body)
        names = [s['name'] for s in signals]
        assert 'suspicious_link' in names

    def test_deep_subdomain(self, analyzer_instance):
        body = '<a href="http://a.b.c.d.evil.com/login">Click here</a>'
        signals = analyzer_instance._analyze_links(body)
        names = [s['name'] for s in signals]
        assert 'suspicious_link' in names

    def test_at_sign_in_url(self, analyzer_instance):
        body = '<a href="http://google.com@evil.com/login">Click here</a>'
        signals = analyzer_instance._analyze_links(body)
        names = [s['name'] for s in signals]
        assert 'suspicious_link' in names

    def test_normal_link_no_signal(self, analyzer_instance):
        body = '<a href="https://www.google.com/search">Search</a>'
        signals = analyzer_instance._analyze_links(body)
        names = [s['name'] for s in signals]
        assert 'suspicious_link' not in names

    def test_image_only_email(self, analyzer_instance):
        body = '<img src="http://evil.com/image.png"><img src="http://evil.com/image2.png">'
        signals = analyzer_instance._analyze_links(body)
        names = [s['name'] for s in signals]
        assert 'image_only_email' in names

    def test_clickable_image(self, analyzer_instance):
        body = '<a href="http://evil.com"><img src="image.png"></a><p>Some text here to avoid image-only</p>'
        signals = analyzer_instance._analyze_links(body)
        names = [s['name'] for s in signals]
        assert 'clickable_image' in names

    def test_suspicious_tld_in_link(self, analyzer_instance):
        body = '<a href="http://evil.xyz/login">Click</a>'
        signals = analyzer_instance._analyze_links(body)
        names = [s['name'] for s in signals]
        assert 'suspicious_link' in names


# ═══════════════════════════════════════════════════════════════════════════════
# Mismatched Links
# ═══════════════════════════════════════════════════════════════════════════════

class TestMismatchedLinks:
    def test_mismatched_link(self, analyzer_instance):
        body = '<a href="http://evil.com/steal">https://paypal.com/login</a>'
        result = analyzer_instance._check_mismatched_links(body)
        assert result is not None
        assert result['name'] == 'mismatched_link'

    def test_matching_link(self, analyzer_instance):
        body = '<a href="https://paypal.com/login">https://paypal.com/login</a>'
        result = analyzer_instance._check_mismatched_links(body)
        assert result is None

    def test_non_url_display_text(self, analyzer_instance):
        """Display text that isn't a URL shouldn't trigger mismatch."""
        body = '<a href="https://example.com/page">Click Here</a>'
        result = analyzer_instance._check_mismatched_links(body)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# Suspicious Attachments
# ═══════════════════════════════════════════════════════════════════════════════

class TestSuspiciousAttachments:
    def test_exe_attachment(self, analyzer_instance):
        headers = 'Content-Disposition: attachment; filename="invoice.exe"'
        result = analyzer_instance._check_suspicious_attachments(headers, '')
        assert result is not None
        assert result['name'] == 'suspicious_attachment'

    def test_password_protected_zip(self, analyzer_instance):
        body = '<p>Please open the attached document.zip. Password: abc123</p>'
        headers = 'Content-Disposition: attachment; filename="document.zip"'
        result = analyzer_instance._check_suspicious_attachments(headers, body)
        assert result is not None

    def test_pdf_not_flagged(self, analyzer_instance):
        headers = 'Content-Disposition: attachment; filename="report.pdf"'
        result = analyzer_instance._check_suspicious_attachments(headers, '')
        assert result is None

    def test_js_attachment(self, analyzer_instance):
        headers = 'Content-Disposition: attachment; filename="update.js"'
        result = analyzer_instance._check_suspicious_attachments(headers, '')
        assert result is not None

    def test_body_url_no_false_positive(self, analyzer_instance):
        """URLs in body mentioning .exe/.js should NOT trigger attachment signal."""
        headers = 'From: user@example.com\nTo: me@example.com'
        body = '<p>Download from http://example.com/update.exe for the latest version.</p>'
        result = analyzer_instance._check_suspicious_attachments(headers, body)
        assert result is None

    def test_body_text_html_no_false_positive(self, analyzer_instance):
        """Body text mentioning .html files should NOT trigger attachment signal."""
        headers = 'From: user@example.com'
        body = '<p>Open the page at https://docs.example.com/guide.html</p>'
        result = analyzer_instance._check_suspicious_attachments(headers, body)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# Financial Keywords
# ═══════════════════════════════════════════════════════════════════════════════

class TestFinancialKeywords:
    def test_wire_transfer(self, analyzer_instance):
        body = '<p>Please complete the wire transfer immediately.</p>'
        result = analyzer_instance._check_financial_keywords(body, '')
        assert result is not None
        assert result['name'] == 'financial_keywords'

    def test_gift_card(self, analyzer_instance):
        body = '<p>Buy iTunes gift card and send the codes.</p>'
        result = analyzer_instance._check_financial_keywords(body, '')
        assert result is not None

    def test_bitcoin(self, analyzer_instance):
        body = '<p>Send 0.5 bitcoin to this wallet address.</p>'
        result = analyzer_instance._check_financial_keywords(body, '')
        assert result is not None

    def test_normal_content(self, analyzer_instance):
        body = '<p>Please review the attached quarterly report.</p>'
        result = analyzer_instance._check_financial_keywords(body, '')
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# Homograph Attack Detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestHomographAttack:
    def test_cyrillic_a(self, analyzer_instance):
        # Cyrillic 'а' (U+0430) looks like Latin 'a'
        body = '<p>Visit p\u0430ypal.com</p>'
        result = analyzer_instance._check_homograph_attack(body, '')
        assert result is not None
        assert result['name'] == 'homograph_attack'

    def test_normal_ascii_no_false_positive(self, analyzer_instance):
        """Normal ASCII text with digits should NOT trigger homograph detection."""
        body = '<p>Order #12345 confirmed at 10:30am. Visit https://example.com/page?id=100</p>'
        result = analyzer_instance._check_homograph_attack(body, 'user@example.com')
        assert result is None

    def test_mixed_script_url(self, analyzer_instance):
        body = '<p>Visit https://g\u043eoogle.com</p>'
        result = analyzer_instance._check_homograph_attack(body, '')
        assert result is not None


# ═══════════════════════════════════════════════════════════════════════════════
# Sender Pattern Detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestSenderPattern:
    def test_random_characters(self, analyzer_instance):
        signals = analyzer_instance._check_sender_pattern(
            'brittenyegil13061993ct@hotmail.com', 'hotmail.com'
        )
        names = [s['name'] for s in signals]
        assert 'suspicious_sender_pattern' in names

    def test_brand_from_freemail(self, analyzer_instance):
        signals = analyzer_instance._check_sender_pattern(
            '"PayPal Security" <xrandom123@gmail.com>', 'gmail.com'
        )
        names = [s['name'] for s in signals]
        assert 'display_name_mismatch' in names

    def test_normal_sender(self, analyzer_instance):
        signals = analyzer_instance._check_sender_pattern(
            'john.smith@company.com', 'company.com'
        )
        assert len(signals) == 0

    def test_year_pattern_freemail(self, analyzer_instance):
        signals = analyzer_instance._check_sender_pattern(
            'randomuser1994@gmail.com', 'gmail.com'
        )
        names = [s['name'] for s in signals]
        assert 'freemail_random' in names


# ═══════════════════════════════════════════════════════════════════════════════
# Vague Subject
# ═══════════════════════════════════════════════════════════════════════════════

class TestVagueSubject:
    def test_just_hi(self, analyzer_instance):
        result = analyzer_instance._check_vague_subject('Hi')
        assert result is not None

    def test_urgent(self, analyzer_instance):
        result = analyzer_instance._check_vague_subject('Urgent')
        assert result is not None

    def test_normal_subject(self, analyzer_instance):
        result = analyzer_instance._check_vague_subject('Q4 2025 Financial Report')
        assert result is None

    def test_empty_subject(self, analyzer_instance):
        result = analyzer_instance._check_vague_subject('')
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# Excessive Links
# ═══════════════════════════════════════════════════════════════════════════════

class TestExcessiveLinks:
    def test_many_links(self, analyzer_instance):
        body = ''.join(f'<a href="http://example{i}.com">Link {i}</a>' for i in range(20))
        result = analyzer_instance._check_excessive_links(body)
        assert result is not None

    def test_few_links(self, analyzer_instance):
        body = '<a href="http://example.com">Link</a><a href="http://example2.com">Link 2</a>'
        result = analyzer_instance._check_excessive_links(body)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# Fingerprint Generation
# ═══════════════════════════════════════════════════════════════════════════════

class TestFingerprint:
    def test_same_email_same_fingerprint(self, analyzer_instance):
        fp1 = analyzer_instance._generate_fingerprint('evil.com', 'Verify account', '<a href="http://evil.com">')
        fp2 = analyzer_instance._generate_fingerprint('evil.com', 'Verify account', '<a href="http://evil.com">')
        assert fp1 == fp2

    def test_different_domain_different_fingerprint(self, analyzer_instance):
        fp1 = analyzer_instance._generate_fingerprint('evil.com', 'Verify', '<a href="http://evil.com">')
        fp2 = analyzer_instance._generate_fingerprint('other.com', 'Verify', '<a href="http://evil.com">')
        assert fp1 != fp2

    def test_forward_prefix_stripped(self, analyzer_instance):
        fp1 = analyzer_instance._generate_fingerprint('evil.com', 'Verify account', '<p>body</p>')
        fp2 = analyzer_instance._generate_fingerprint('evil.com', 'RE: Verify account', '<p>body</p>')
        assert fp1 == fp2

    def test_numbers_normalized(self, analyzer_instance):
        fp1 = analyzer_instance._generate_fingerprint('evil.com', 'Invoice 12345', '<p>body</p>')
        fp2 = analyzer_instance._generate_fingerprint('evil.com', 'Invoice 67890', '<p>body</p>')
        assert fp1 == fp2


# ═══════════════════════════════════════════════════════════════════════════════
# HTML to Text
# ═══════════════════════════════════════════════════════════════════════════════

class TestHtmlToText:
    def test_strips_tags(self, analyzer_instance):
        result = analyzer_instance._html_to_text('<p>Hello <b>world</b></p>')
        assert 'Hello' in result
        assert 'world' in result
        assert '<' not in result

    def test_handles_entities(self, analyzer_instance):
        result = analyzer_instance._html_to_text('&amp; &lt; &gt;')
        assert '&' in result
        assert '<' in result
        assert '>' in result

    def test_empty_input(self, analyzer_instance):
        assert analyzer_instance._html_to_text('') == ''
        assert analyzer_instance._html_to_text(None) == ''


# ═══════════════════════════════════════════════════════════════════════════════
# Full Analysis (End-to-End)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullAnalysis:
    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_domain_age', return_value=None)
    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_dns_records', return_value=[])
    def test_phishing_email_detected(self, mock_dns, mock_age, analyzer_instance):
        result = analyzer_instance.analyze(
            PHISHING_HEADERS_O365, PHISHING_BODY,
            'security@paypa1.xyz', 'Urgent: Verify your account'
        )
        assert result['verdict'] == 'phishing'
        assert result['confidence'] >= 70

    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_domain_age', return_value=None)
    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_dns_records', return_value=[])
    def test_safe_email_detected(self, mock_dns, mock_age, analyzer_instance):
        result = analyzer_instance.analyze(
            SAFE_HEADERS, SAFE_BODY,
            'noreply@microsoft.com', 'Your monthly report'
        )
        assert result['verdict'] == 'safe'
        assert result['confidence'] < 40

    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_domain_age', return_value=None)
    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_dns_records', return_value=[])
    def test_result_has_required_fields(self, mock_dns, mock_age, analyzer_instance):
        result = analyzer_instance.analyze(SAFE_HEADERS, SAFE_BODY, 'user@example.com', 'Test')
        assert 'verdict' in result
        assert 'confidence' in result
        assert 'signals' in result
        assert 'fingerprint' in result
        assert 'sender_domain' in result

    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_domain_age', return_value=None)
    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_dns_records', return_value=[])
    def test_confidence_capped_at_100(self, mock_dns, mock_age, analyzer_instance):
        """Even with many signals, confidence should not exceed 100."""
        result = analyzer_instance.analyze(
            PHISHING_HEADERS_O365, PHISHING_BODY,
            'security@paypa1.xyz', 'Urgent: Verify your account'
        )
        assert result['confidence'] <= 100

    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_domain_age', return_value=None)
    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_dns_records', return_value=[])
    def test_confidence_not_negative(self, mock_dns, mock_age, analyzer_instance):
        """Even with whitelist signal, confidence should not go below 0."""
        from models import add_to_whitelist
        add_to_whitelist('domain', 'safe-company.com', 'Trusted partner', 'admin')
        result = analyzer_instance.analyze(
            SAFE_HEADERS, SAFE_BODY,
            'user@safe-company.com', 'Invoice'
        )
        assert result['confidence'] >= 0

    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_domain_age', return_value=None)
    @patch.object(__import__('analyzer').EmailAnalyzer, '_check_dns_records', return_value=[])
    def test_verdict_thresholds(self, mock_dns, mock_age, analyzer_instance):
        """Verify verdict thresholds are respected."""
        assert analyzer_instance.threshold_phishing == 70
        assert analyzer_instance.threshold_suspicious == 40


# ═══════════════════════════════════════════════════════════════════════════════
# String Similarity (Levenshtein)
# ═══════════════════════════════════════════════════════════════════════════════

class TestStringSimilarity:
    def test_identical_strings(self, analyzer_instance):
        assert analyzer_instance._similar('microsoft', 'microsoft') == 1.0

    def test_empty_strings(self, analyzer_instance):
        assert analyzer_instance._similar('', 'test') == 0
        assert analyzer_instance._similar('test', '') == 0
        assert analyzer_instance._similar('', '') == 0

    def test_one_char_difference(self, analyzer_instance):
        ratio = analyzer_instance._similar('microsoft', 'microsoft')
        assert ratio > 0.8

    def test_shifted_string_detected(self, analyzer_instance):
        """The old positional comparison missed shifted strings. Levenshtein catches them."""
        ratio = analyzer_instance._similar('xmicrosoft', 'microsoft')
        assert ratio > 0.8

    def test_completely_different(self, analyzer_instance):
        ratio = analyzer_instance._similar('abcdef', 'zyxwvu')
        assert ratio < 0.3

    def test_similar_brand_lookalikes(self, analyzer_instance):
        assert analyzer_instance._similar('micr0soft', 'microsoft') > 0.8
        assert analyzer_instance._similar('arnazon', 'amazon') > 0.7
