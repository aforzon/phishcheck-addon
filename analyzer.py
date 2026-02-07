"""
Email Phishing Analyzer

Parses email headers and content to determine phishing likelihood.
Combines Microsoft O365 signals with internal checks.
"""

import re
import hashlib
import dns.resolver
from datetime import datetime, timedelta
from functools import lru_cache
from urllib.parse import urlparse
import logging

import config
from models import is_whitelisted, is_blacklisted

logger = logging.getLogger(__name__)


# DNS result cache — avoids redundant lookups for the same domain
# maxsize=256 keeps the most recent 256 domains; cleared on process restart
@lru_cache(maxsize=256)
def _dns_resolve(domain, rdtype):
    """Cached DNS resolution. Returns list of record strings, or None on failure."""
    try:
        answers = dns.resolver.resolve(domain, rdtype)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.Timeout):
        return None
    except Exception:
        return None


# Optional URL detonation
try:
    from urlscan_detonator import URLScanDetonator
    URLSCAN_AVAILABLE = True
except ImportError:
    URLSCAN_AVAILABLE = False
    logger.info("urlscan_detonator not available - URL detonation disabled")


class EmailAnalyzer:
    def __init__(self):
        self.weights = config.WEIGHTS
        self.suspicious_tlds = config.SUSPICIOUS_TLDS
        self.threshold_phishing = config.THRESHOLD_PHISHING
        self.threshold_suspicious = config.THRESHOLD_SUSPICIOUS

        # URL detonation setup
        self.detonator = None
        if URLSCAN_AVAILABLE and config.ENABLE_URL_DETONATION and config.URLSCAN_API_KEY:
            try:
                self.detonator = URLScanDetonator(
                    api_key=config.URLSCAN_API_KEY,
                    output_dir=config.DETONATION_OUTPUT_DIR
                )
                logger.info("URL detonation enabled via urlscan.io")
            except Exception as e:
                logger.warning(f"Failed to initialize URL detonator: {e}")

    def analyze(self, headers, body_html, sender, subject):
        """
        Analyze an email and return verdict with confidence score.

        Args:
            headers: Raw email headers (string)
            body_html: Email body HTML
            sender: Sender email address
            subject: Email subject

        Returns:
            dict with: verdict, confidence, signals, fingerprint
        """
        signals = []
        score = 0

        # Extract sender domain
        sender_domain = self._extract_domain(sender)

        # Check whitelist/blacklist first
        if is_whitelisted(sender, sender_domain):
            signals.append({
                'name': 'whitelist',
                'description': 'Sender is on internal whitelist',
                'weight': self.weights['whitelist']
            })
            score += self.weights['whitelist']

        if is_blacklisted(sender, sender_domain):
            signals.append({
                'name': 'blacklist',
                'description': 'Sender is on internal blacklist',
                'weight': self.weights['blacklist']
            })
            score += self.weights['blacklist']

        # Parse Microsoft O365 headers
        o365_signals = self._parse_o365_headers(headers)
        for signal in o365_signals:
            signals.append(signal)
            score += signal['weight']

        # Internal checks
        internal_signals = self._internal_checks(sender, sender_domain, subject, body_html, headers)
        for signal in internal_signals:
            signals.append(signal)
            score += signal['weight']

        # Calculate confidence (cap at 100)
        confidence = min(max(score, 0), 100)

        # Determine verdict
        if confidence >= self.threshold_phishing:
            verdict = 'phishing'
        elif confidence >= self.threshold_suspicious:
            verdict = 'suspicious'
        else:
            verdict = 'safe'

        # Generate fingerprint for campaign detection
        fingerprint = self._generate_fingerprint(sender_domain, subject, body_html)

        return {
            'verdict': verdict,
            'confidence': confidence,
            'signals': signals,
            'fingerprint': fingerprint,
            'sender_domain': sender_domain
        }

    def _extract_domain(self, email):
        """Extract domain from email address."""
        if not email:
            return ''
        match = re.search(r'@([^\s>]+)', email)
        return match.group(1).lower() if match else ''

    def _parse_o365_headers(self, headers):
        """
        Parse Microsoft O365 antispam headers.

        Headers we look for:
        - Authentication-Results: SPF, DKIM, DMARC results
        - X-Forefront-Antispam-Report: CAT (category), SCL, PCL
        - X-MS-Exchange-Organization-SCL: Spam confidence level
        """
        signals = []
        if not headers:
            return signals

        # Check Authentication-Results for SPF/DKIM/DMARC
        auth_results = self._find_header(headers, 'Authentication-Results')
        if auth_results:
            # SPF check
            if 'spf=fail' in auth_results.lower() or 'spf=softfail' in auth_results.lower():
                signals.append({
                    'name': 'spf_fail',
                    'description': 'SPF authentication failed - sender IP not authorized',
                    'weight': self.weights['spf_fail']
                })

            # DKIM check
            if 'dkim=fail' in auth_results.lower():
                signals.append({
                    'name': 'dkim_fail',
                    'description': 'DKIM signature verification failed',
                    'weight': self.weights['dkim_fail']
                })

            # DMARC check
            if 'dmarc=fail' in auth_results.lower():
                signals.append({
                    'name': 'dmarc_fail',
                    'description': 'DMARC policy check failed',
                    'weight': self.weights['dmarc_fail']
                })

        # Check X-Forefront-Antispam-Report
        antispam = self._find_header(headers, 'X-Forefront-Antispam-Report')
        if antispam:
            # Check CAT (category) - PHSH means Microsoft flagged as phishing
            if 'cat:phsh' in antispam.lower():
                signals.append({
                    'name': 'microsoft_phishing',
                    'description': 'Microsoft flagged this as phishing',
                    'weight': self.weights['microsoft_phishing']
                })

            # Check SCL (Spam Confidence Level)
            scl_match = re.search(r'scl:(\d+)', antispam.lower())
            if scl_match:
                scl = int(scl_match.group(1))
                if scl >= 7:
                    signals.append({
                        'name': 'high_scl',
                        'description': f'High spam confidence level (SCL={scl})',
                        'weight': self.weights['high_scl']
                    })

            # Check PCL (Phishing Confidence Level)
            pcl_match = re.search(r'pcl:(\d+)', antispam.lower())
            if pcl_match:
                pcl = int(pcl_match.group(1))
                if pcl >= 5:
                    signals.append({
                        'name': 'high_pcl',
                        'description': f'High phishing confidence level (PCL={pcl})',
                        'weight': self.weights['high_pcl']
                    })

        # Also check X-MS-Exchange-Organization-SCL
        org_scl = self._find_header(headers, 'X-MS-Exchange-Organization-SCL')
        if org_scl:
            try:
                scl = int(org_scl.strip())
                if scl >= 7 and not any(s['name'] == 'high_scl' for s in signals):
                    signals.append({
                        'name': 'high_scl',
                        'description': f'High spam confidence level (SCL={scl})',
                        'weight': self.weights['high_scl']
                    })
            except ValueError:
                pass

        return signals

    def _find_header(self, headers, header_name):
        """Find a specific header value in headers string."""
        pattern = rf'^{re.escape(header_name)}:\s*(.+?)(?=\n[^\s]|\Z)'
        match = re.search(pattern, headers, re.MULTILINE | re.IGNORECASE | re.DOTALL)
        if match:
            # Handle folded headers (continuation lines starting with whitespace)
            value = match.group(1)
            value = re.sub(r'\n\s+', ' ', value)
            return value.strip()
        return None

    def _internal_checks(self, sender, sender_domain, subject, body_html, headers):
        """
        Perform internal checks that Microsoft doesn't do.
        """
        signals = []

        # Check for suspicious sender email patterns
        sender_signals = self._check_sender_pattern(sender, sender_domain)
        signals.extend(sender_signals)

        # Reply-To mismatch
        reply_to = self._find_header(headers, 'Reply-To') if headers else None
        if reply_to:
            reply_domain = self._extract_domain(reply_to)
            if reply_domain and reply_domain != sender_domain:
                signals.append({
                    'name': 'reply_to_mismatch',
                    'description': f'Reply-To domain ({reply_domain}) differs from sender ({sender_domain})',
                    'weight': self.weights['reply_to_mismatch']
                })

        # Lookalike domain detection
        if sender_domain and self._is_lookalike_domain(sender_domain):
            signals.append({
                'name': 'lookalike_domain',
                'description': f'Sender domain appears to impersonate a known brand',
                'weight': self.weights['lookalike_domain']
            })

        # Suspicious TLD
        if sender_domain:
            for tld in self.suspicious_tlds:
                if sender_domain.endswith(tld):
                    signals.append({
                        'name': 'suspicious_tld',
                        'description': f'Sender uses suspicious TLD ({tld})',
                        'weight': self.weights['suspicious_tld']
                    })
                    break

        # Domain age check (if we can look it up)
        domain_age_signal = self._check_domain_age(sender_domain)
        if domain_age_signal:
            signals.append(domain_age_signal)

        # DNS record checks (MX, SPF, DMARC)
        dns_signals = self._check_dns_records(sender_domain)
        if dns_signals:
            signals.extend(dns_signals)

        # Vague/suspicious subject line
        if subject:
            vague_subject = self._check_vague_subject(subject)
            if vague_subject:
                signals.append(vague_subject)

        # Content analysis
        if body_html:
            content_signals = self._analyze_content(body_html, subject)
            signals.extend(content_signals)

        # Link analysis
        if body_html:
            link_signals = self._analyze_links(body_html)
            signals.extend(link_signals)

        # Additional checks
        if body_html:
            # Mismatched link text
            mismatched = self._check_mismatched_links(body_html)
            if mismatched:
                signals.append(mismatched)

            # Financial keywords
            financial = self._check_financial_keywords(body_html, subject)
            if financial:
                signals.append(financial)

            # Excessive links
            excessive = self._check_excessive_links(body_html)
            if excessive:
                signals.append(excessive)

            # Homograph/Unicode attack
            homograph = self._check_homograph_attack(body_html, sender)
            if homograph:
                signals.append(homograph)

        # Suspicious attachments (check headers for Content-Disposition)
        if headers:
            attachment = self._check_suspicious_attachments(headers, body_html)
            if attachment:
                signals.append(attachment)

        # URL detonation (if enabled and suspicious indicators found)
        if body_html and self.detonator:
            # Only detonate if we already have some suspicious signals
            current_score = sum(s['weight'] for s in signals)
            if current_score >= 20:  # Only detonate if already somewhat suspicious
                urls = self._extract_urls(body_html)
                if urls:
                    detonation_signals = self._detonate_urls(urls)
                    signals.extend(detonation_signals)

        return signals

    def _check_sender_pattern(self, sender, sender_domain):
        """
        Check for suspicious patterns in sender email address.

        Detects:
        - Random character patterns (e.g., brittenyegil13061993ct@hotmail.com)
        - Display name vs email mismatch (e.g., "PayPal" <randomuser@gmail.com>)
        - Freemail with suspicious local part
        """
        signals = []
        if not sender:
            return signals

        # Extract display name and email
        display_name = ''
        email_addr = sender
        if '<' in sender:
            parts = sender.split('<')
            display_name = parts[0].strip().strip('"\'')
            email_addr = parts[1].rstrip('>')

        local_part = email_addr.split('@')[0] if '@' in email_addr else ''

        # Freemail providers
        freemail_domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'mail.com', 'protonmail.com', 'icloud.com',
            'live.com', 'msn.com', 'ymail.com'
        ]

        is_freemail = sender_domain in freemail_domains

        # Check 1: Random character pattern in local part
        # Indicators: long string, mix of letters and numbers, no clear words
        if local_part and len(local_part) > 12:
            digit_count = sum(c.isdigit() for c in local_part)
            letter_count = sum(c.isalpha() for c in local_part)

            # Many digits mixed with letters = suspicious
            if digit_count >= 4 and letter_count >= 6:
                signals.append({
                    'name': 'suspicious_sender_pattern',
                    'description': 'Sender email has random character pattern typical of spam',
                    'weight': self.weights.get('suspicious_sender_pattern', 15)
                })
            # Very long with no common separators = suspicious
            elif len(local_part) > 20 and '.' not in local_part and '_' not in local_part:
                signals.append({
                    'name': 'suspicious_sender_pattern',
                    'description': 'Sender email has unusually long random pattern',
                    'weight': self.weights.get('suspicious_sender_pattern', 15)
                })

        # Check 2: Display name vs email mismatch
        if display_name and is_freemail:
            # Known brand names that shouldn't come from freemail
            brand_keywords = [
                'paypal', 'amazon', 'microsoft', 'apple', 'google', 'bank',
                'netflix', 'facebook', 'instagram', 'support', 'security',
                'admin', 'helpdesk', 'service', 'account', 'verify'
            ]
            display_lower = display_name.lower()
            for brand in brand_keywords:
                if brand in display_lower:
                    signals.append({
                        'name': 'display_name_mismatch',
                        'description': f'Display name "{display_name}" but sent from freemail ({sender_domain})',
                        'weight': self.weights.get('display_name_mismatch', 10)
                    })
                    break

        # Check 3: Freemail with suspicious random local part
        if is_freemail and local_part:
            # Year pattern at end (common in spam: name1994, john2023)
            if re.search(r'(19|20)\d{2}[a-z]{0,3}$', local_part):
                signals.append({
                    'name': 'freemail_random',
                    'description': 'Freemail with suspicious year-based email pattern',
                    'weight': self.weights.get('freemail_random', 10)
                })

        # Check 4: Display name doesn't match email local part
        if display_name and local_part:
            # Normalize both for comparison
            display_words = re.findall(r'[a-z]+', display_name.lower())
            local_clean = re.sub(r'[^a-z]', '', local_part.lower())

            # If display name has words but none appear in email
            if display_words and len(display_words) > 0:
                has_match = any(word in local_clean for word in display_words if len(word) > 3)
                if not has_match and len(local_clean) > 5:
                    signals.append({
                        'name': 'display_email_mismatch',
                        'description': f'Display name "{display_name}" doesn\'t match email address',
                        'weight': self.weights.get('display_email_mismatch', 10)
                    })

        return signals

    def _check_vague_subject(self, subject):
        """Check for vague or suspicious subject lines."""
        if not subject:
            return None

        subject_lower = subject.lower().strip()

        # Very short/vague subjects
        vague_patterns = [
            r'^(re:|fw:|fwd:)?\s*(hi|hello|hey|update|info|news|alert|notice|important)\s*:?\s*$',
            r'^(re:|fw:|fwd:)?\s*new\s+(update|message|info|alert)\s*:?\s*\w{0,5}$',
            r'^(re:|fw:|fwd:)?\s*(urgent|action|verify|confirm)\s*:?\s*$',
            r'^(re:|fw:|fwd:)?\s*\w{1,3}\s*:?\s*$',  # Very short like "DC:" or "Hi"
        ]

        for pattern in vague_patterns:
            if re.match(pattern, subject_lower, re.IGNORECASE):
                return {
                    'name': 'vague_subject',
                    'description': 'Email has vague/generic subject line typical of spam',
                    'weight': self.weights.get('vague_subject', 5)
                }

        return None

    def _is_lookalike_domain(self, domain):
        """
        Check if domain is a lookalike of known brands.

        Common substitutions: 0 for o, 1 for l/i, rn for m, etc.
        """
        known_brands = [
            'microsoft', 'paypal', 'amazon', 'apple', 'google', 'facebook',
            'netflix', 'linkedin', 'dropbox', 'docusign', 'adobe', 'office365',
            'outlook', 'onedrive', 'sharepoint', 'teams', 'zoom', 'slack',
            'bank', 'chase', 'wellsfargo', 'citibank', 'usps', 'fedex', 'ups',
            'dhl', 'irs', 'socialsecurity'
        ]

        # Normalize domain for comparison
        domain_base = domain.split('.')[0].lower()

        # Common substitutions
        normalized = domain_base
        normalized = normalized.replace('0', 'o')
        normalized = normalized.replace('1', 'l')
        normalized = normalized.replace('rn', 'm')
        normalized = normalized.replace('vv', 'w')
        normalized = re.sub(r'[^a-z]', '', normalized)

        # Check for brand matches
        for brand in known_brands:
            # Direct lookalike
            if normalized == brand and domain_base != brand:
                return True

            # Contains brand with extra chars (e.g., paypal-secure)
            if brand in domain_base and domain_base != brand:
                return True

            # Levenshtein-like check for similar strings
            if self._similar(normalized, brand) > 0.8 and normalized != brand:
                return True

        return False

    def _similar(self, a, b):
        """Similarity ratio using Levenshtein edit distance."""
        if not a or not b:
            return 0
        if a == b:
            return 1.0
        len_a, len_b = len(a), len(b)
        # Quick reject if lengths are too different
        if abs(len_a - len_b) > max(len_a, len_b) * 0.5:
            return 0
        # Levenshtein distance via single-row DP
        prev = list(range(len_b + 1))
        for i in range(1, len_a + 1):
            curr = [i] + [0] * len_b
            for j in range(1, len_b + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            prev = curr
        distance = prev[len_b]
        return 1.0 - distance / max(len_a, len_b)

    def _check_domain_age(self, domain):
        """
        Check domain patterns and resolvability via DNS.

        Note: Full WHOIS lookup would be more accurate but requires external API.
        This is a simplified check based on DNS record existence and name patterns.
        """
        if not domain:
            return None

        # Use cached DNS resolution
        a_records = _dns_resolve(domain, 'A')

        if a_records is not None:
            # Domain resolves — check for suspicious name patterns
            suspicious_patterns = [
                r'\d{4,}',  # Contains 4+ digits
                r'-[a-z]{2,}-',  # Multiple hyphenated segments
                r'(secure|verify|update|account|login|confirm)',  # Phishy keywords
            ]

            for pattern in suspicious_patterns:
                if re.search(pattern, domain.lower()):
                    return {
                        'name': 'domain_age_30',
                        'description': 'Domain has suspicious registration pattern',
                        'weight': self.weights['domain_age_30']
                    }

            return None
        else:
            # Domain doesn't exist or can't be resolved
            return {
                'name': 'domain_age_7',
                'description': 'Domain cannot be resolved (may be very new or fake)',
                'weight': self.weights['domain_age_7']
            }

    def _check_dns_records(self, domain):
        """
        Check DNS records for the sender domain.
        Missing MX, SPF, or DMARC records can indicate phishing domains.
        Uses cached DNS resolution to avoid redundant lookups.
        """
        signals = []

        if not domain:
            return signals

        # Skip common freemail providers (they definitely have DNS records)
        freemail_domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'mail.com', 'protonmail.com',
            'live.com', 'msn.com', 'ymail.com'
        ]
        if domain.lower() in freemail_domains:
            return signals

        # Check MX records (cached)
        mx_records = _dns_resolve(domain, 'MX')
        has_mx = mx_records is not None and len(mx_records) > 0

        if not has_mx:
            signals.append({
                'name': 'no_mx_record',
                'description': f'Domain {domain} has no MX records (cannot receive email)',
                'weight': self.weights.get('no_mx_record', 15)
            })

        # Check SPF record (cached)
        txt_records = _dns_resolve(domain, 'TXT')
        has_spf = txt_records is not None and any('v=spf1' in r.lower() for r in txt_records)

        if not has_spf:
            signals.append({
                'name': 'no_spf_record',
                'description': f'Domain {domain} has no SPF record (email authentication not configured)',
                'weight': self.weights.get('no_spf_record', 10)
            })

        # Check DMARC record (cached)
        dmarc_domain = f'_dmarc.{domain}'
        dmarc_records = _dns_resolve(dmarc_domain, 'TXT')
        has_dmarc = dmarc_records is not None and any('v=dmarc1' in r.lower() for r in dmarc_records)

        if not has_dmarc:
            signals.append({
                'name': 'no_dmarc_record',
                'description': f'Domain {domain} has no DMARC record (email policy not configured)',
                'weight': self.weights.get('no_dmarc_record', 5)
            })

        if signals:
            logger.info(f'DNS checks for {domain}: MX={has_mx}, SPF={has_spf}, DMARC={has_dmarc}')

        return signals

    def _analyze_content(self, body_html, subject):
        """Analyze email content for phishing indicators."""
        signals = []
        text = self._html_to_text(body_html).lower()
        subject_lower = (subject or '').lower()
        combined = f'{subject_lower} {text}'

        # Urgency language
        urgency_patterns = [
            r'urgent', r'immediate(ly)?', r'act now', r'expires? (today|soon|in \d+)',
            r'last chance', r'final notice', r'suspended', r'locked',
            r'within \d+ (hour|day)', r'limited time', r'don\'t delay'
        ]
        for pattern in urgency_patterns:
            if re.search(pattern, combined):
                signals.append({
                    'name': 'urgency_language',
                    'description': 'Email uses urgency language to pressure quick action',
                    'weight': self.weights['urgency_language']
                })
                break

        # Credential request
        credential_patterns = [
            r'(verify|confirm|update).{0,20}(password|account|identity|information)',
            r'(enter|provide).{0,20}(credentials|password|ssn|social security)',
            r'click.{0,30}(verify|confirm|secure)',
            r'reset.{0,20}password'
        ]
        for pattern in credential_patterns:
            if re.search(pattern, combined):
                signals.append({
                    'name': 'credential_request',
                    'description': 'Email requests credential or identity verification',
                    'weight': self.weights['credential_request']
                })
                break

        # Generic greeting
        generic_patterns = [
            r'^dear (customer|user|member|client|sir|madam)',
            r'^dear valued (customer|user|member)',
            r'^hello,?\s*$',
            r'^dear account holder'
        ]
        for pattern in generic_patterns:
            if re.search(pattern, text, re.MULTILINE):
                signals.append({
                    'name': 'generic_greeting',
                    'description': 'Email uses generic greeting instead of your name',
                    'weight': self.weights['generic_greeting']
                })
                break

        return signals

    def _analyze_links(self, body_html):
        """Analyze links in email for suspicious patterns."""
        signals = []

        # Extract all URLs
        url_pattern = r'href=["\']([^"\']+)["\']'
        urls = re.findall(url_pattern, body_html, re.IGNORECASE)

        for url in urls:
            if self._is_suspicious_url(url):
                signals.append({
                    'name': 'suspicious_link',
                    'description': f'Email contains suspicious link',
                    'weight': self.weights['suspicious_link']
                })
                break  # Only count once

        # Check for image-only email (common phishing tactic)
        img_count = len(re.findall(r'<img\s', body_html, re.IGNORECASE))
        text_content = self._html_to_text(body_html)
        text_words = len(text_content.split())

        if img_count > 0 and text_words < 20:
            signals.append({
                'name': 'image_only_email',
                'description': 'Email is mostly images with little text (common phishing tactic)',
                'weight': self.weights.get('image_only_email', 15)
            })

        # Check for clickable images (images wrapped in links)
        clickable_img = re.search(r'<a[^>]*>\s*<img', body_html, re.IGNORECASE)
        if clickable_img:
            signals.append({
                'name': 'clickable_image',
                'description': 'Email contains clickable image (often used to bypass text filters)',
                'weight': self.weights.get('clickable_image', 10)
            })

        # Check for image maps (another way to hide links)
        if '<map' in body_html.lower() or 'usemap=' in body_html.lower():
            if 'clickable_image' not in [s['name'] for s in signals]:
                signals.append({
                    'name': 'clickable_image',
                    'description': 'Email uses image map for hidden clickable areas',
                    'weight': self.weights.get('clickable_image', 10)
                })

        return signals

    def _is_suspicious_url(self, url):
        """Check if a URL is suspicious."""
        if not url or url.startswith('mailto:'):
            return False

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # IP address instead of domain
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                return True

            # Suspicious TLD
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    return True

            # Long subdomain (often used to hide real domain)
            if domain.count('.') > 3:
                return True

            # URL shortener
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'is.gd', 'buff.ly']
            if any(s in domain for s in shorteners):
                return True

            # Contains @ symbol (URL obfuscation)
            if '@' in url:
                return True

            # Cloud storage with random subdomain (common phishing tactic)
            cloud_hosts = [
                'digitaloceanspaces.com', 's3.amazonaws.com', 'blob.core.windows.net',
                'storage.googleapis.com', 'firebasestorage.googleapis.com',
                'cloudfront.net', 'netlify.app', 'vercel.app', 'herokuapp.com',
                'web.app', 'pages.dev', 'workers.dev'
            ]
            for host in cloud_hosts:
                if host in domain:
                    # Check if subdomain looks random (long alphanumeric)
                    subdomain = domain.replace(host, '').rstrip('.')
                    if len(subdomain) > 15 and re.match(r'^[a-z0-9]+$', subdomain.replace('.', '')):
                        return True

            # Random-looking subdomain pattern
            parts = domain.split('.')
            if len(parts) > 2:
                subdomain = parts[0]
                # Long random-looking subdomain
                if len(subdomain) > 20 and re.match(r'^[a-z0-9]+$', subdomain):
                    return True

            return False

        except Exception:
            return True  # Malformed URL is suspicious

    def _html_to_text(self, html):
        """Simple HTML to text conversion."""
        if not html:
            return ''
        # Remove tags
        text = re.sub(r'<[^>]+>', ' ', html)
        # Decode entities
        text = text.replace('&nbsp;', ' ')
        text = text.replace('&amp;', '&')
        text = text.replace('&lt;', '<')
        text = text.replace('&gt;', '>')
        # Collapse whitespace
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _check_mismatched_links(self, body_html):
        """
        Check for links where displayed text doesn't match the href.
        E.g., <a href="http://evil.com">https://paypal.com</a>
        """
        # Find all <a> tags with href and text content
        pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
        matches = re.findall(pattern, body_html, re.IGNORECASE)

        for href, display_text in matches:
            display_text = display_text.strip()

            # Skip if display text is not a URL
            if not re.match(r'https?://', display_text, re.IGNORECASE):
                continue

            # Extract domains from both
            try:
                href_domain = urlparse(href).netloc.lower().replace('www.', '')
                display_domain = urlparse(display_text).netloc.lower().replace('www.', '')

                # If both are URLs but domains don't match = phishing trick
                if href_domain and display_domain and href_domain != display_domain:
                    return {
                        'name': 'mismatched_link',
                        'description': f'Link text shows "{display_domain}" but actually goes to "{href_domain}"',
                        'weight': self.weights.get('mismatched_link', 20)
                    }
            except Exception:
                pass

        return None

    def _check_suspicious_attachments(self, headers, body_html):
        """
        Check for suspicious attachment types in headers only.
        """
        dangerous_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',  # Executables
            '.js', '.jse', '.vbs', '.vbe', '.wsf', '.wsh',   # Scripts
            '.msi', '.msp', '.hta', '.cpl',                   # Installers
            '.jar', '.ps1', '.psm1',                          # Java/PowerShell
            '.iso', '.img',                                    # Disk images
        ]

        # Only search headers for Content-Disposition / filename patterns
        # Searching body_html causes false positives on URLs/text mentioning filenames
        headers_lower = (headers or '').lower()

        filename_matches = re.findall(r'filename["\s]*=[\s"\']*([^"\'\s;>]+)', headers_lower)

        for filename in filename_matches:
            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    return {
                        'name': 'suspicious_attachment',
                        'description': f'Contains suspicious attachment type ({ext})',
                        'weight': self.weights.get('suspicious_attachment', 20)
                    }

        # Check for .zip with password hint in body (common malware delivery)
        combined_lower = headers_lower + (body_html or '').lower()
        has_zip_attachment = re.search(r'filename["\s]*=[\s"\']*[^"\'\s;>]*\.zip', headers_lower)
        if has_zip_attachment and ('password' in combined_lower or 'pwd:' in combined_lower):
            return {
                'name': 'suspicious_attachment',
                'description': 'Password-protected ZIP attachment (common malware delivery)',
                'weight': self.weights.get('suspicious_attachment', 20)
            }

        return None

    def _check_financial_keywords(self, body_html, subject):
        """
        Check for financial/payment keywords often used in scams.
        """
        text = self._html_to_text(body_html).lower()
        subject_lower = (subject or '').lower()
        combined = f'{subject_lower} {text}'

        financial_patterns = [
            r'wire\s*transfer',
            r'bank\s*transfer',
            r'gift\s*card',
            r'bitcoin|btc|cryptocurrency|crypto\s*wallet',
            r'western\s*union',
            r'moneygram',
            r'itunes\s*card',
            r'google\s*play\s*card',
            r'steam\s*card',
            r'payment\s*(of|for)\s*\$?\d+',
            r'\$\d{1,3}(,\d{3})+',  # Large dollar amounts
            r'send\s*(money|funds|payment)',
            r'refund.{0,20}(credit|debit)\s*card',
            r'irs|tax\s*refund|tax\s*return',
        ]

        for pattern in financial_patterns:
            if re.search(pattern, combined):
                return {
                    'name': 'financial_keywords',
                    'description': 'Email contains financial/payment keywords often used in scams',
                    'weight': self.weights.get('financial_keywords', 10)
                }

        return None

    def _check_excessive_links(self, body_html):
        """
        Check for excessive number of links in email.
        """
        # Count unique links
        links = re.findall(r'href=["\']([^"\']+)["\']', body_html, re.IGNORECASE)

        # Filter out mailto and anchors
        http_links = [l for l in links if l.startswith('http')]

        if len(http_links) > 15:
            return {
                'name': 'excessive_links',
                'description': f'Email contains excessive links ({len(http_links)} links)',
                'weight': self.weights.get('excessive_links', 10)
            }

        return None

    def _check_homograph_attack(self, body_html, sender):
        """
        Check for homograph/Unicode attacks using lookalike characters.
        E.g., using Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061)
        """
        # Common lookalike characters (Cyrillic, Greek, etc.)
        homoglyphs = {
            'а': 'a',  # Cyrillic
            'е': 'e',  # Cyrillic
            'о': 'o',  # Cyrillic
            'р': 'p',  # Cyrillic
            'с': 'c',  # Cyrillic
            'у': 'y',  # Cyrillic
            'х': 'x',  # Cyrillic
            'і': 'i',  # Cyrillic/Ukrainian
            'ј': 'j',  # Cyrillic
            'ѕ': 's',  # Cyrillic
            'ԁ': 'd',  # Cyrillic
            'ɡ': 'g',  # Latin small letter script g
            'ո': 'n',  # Armenian
            'ν': 'v',  # Greek nu
            'ω': 'w',  # Greek omega
            'ɑ': 'a',  # Latin alpha
            'ß': 'b',  # German eszett (looks like B)
        }
        # Note: '0' and '1' (ASCII digits) are intentionally excluded.
        # They appear in virtually every email (URLs, styles, etc.)
        # and would cause false positives on every analysis.

        # Check sender email
        text_to_check = (sender or '') + (body_html or '')

        # Look for non-ASCII characters that look like ASCII
        for char, lookalike in homoglyphs.items():
            if char in text_to_check:
                return {
                    'name': 'homograph_attack',
                    'description': f'Email contains lookalike Unicode characters (possible homograph attack)',
                    'weight': self.weights.get('homograph_attack', 25)
                }

        # Also check for mixed scripts in domains (e.g., latin + cyrillic)
        urls = re.findall(r'https?://([^\s/<>"\']+)', text_to_check)
        for url in urls:
            # Check if URL contains both ASCII and non-ASCII letters
            has_ascii = bool(re.search(r'[a-zA-Z]', url))
            has_nonascii = bool(re.search(r'[^\x00-\x7F]', url))
            if has_ascii and has_nonascii:
                return {
                    'name': 'homograph_attack',
                    'description': f'URL contains mixed character sets (homograph attack indicator)',
                    'weight': self.weights.get('homograph_attack', 25)
                }

        return None

    def _generate_fingerprint(self, sender_domain, subject, body_html):
        """
        Generate fingerprint for campaign detection.

        Same fingerprint = likely same campaign.
        """
        # Normalize subject (remove RE:, FW:, numbers)
        subject_norm = re.sub(r'^(re:|fw:|fwd:)\s*', '', (subject or '').lower(), flags=re.IGNORECASE)
        subject_norm = re.sub(r'\d+', '#', subject_norm)

        # Extract links from body
        links = sorted(set(re.findall(r'href=["\']([^"\']+)["\']', body_html or '', re.IGNORECASE)))
        links_str = '|'.join(links[:5])  # Top 5 links

        # Create fingerprint
        fingerprint_data = f'{sender_domain}|{subject_norm}|{links_str}'
        return hashlib.md5(fingerprint_data.encode()).hexdigest()

    def _extract_urls(self, body_html):
        """Extract all unique URLs from email body."""
        if not body_html:
            return []

        # Extract href URLs
        href_urls = re.findall(r'href=["\']([^"\']+)["\']', body_html, re.IGNORECASE)

        # Extract plain text URLs
        text_urls = re.findall(r'https?://[^\s<>"\']+', body_html)

        # Combine and dedupe
        all_urls = list(set(href_urls + text_urls))

        # Filter out non-http(s) and common safe domains
        safe_domains = [
            'microsoft.com', 'google.com', 'apple.com', 'amazon.com',
            'facebook.com', 'linkedin.com', 'twitter.com', 'github.com',
            'outlook.com', 'office.com', 'live.com'
        ]

        filtered = []
        for url in all_urls:
            if not url.startswith('http'):
                continue

            # Skip known safe domains
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                if any(safe in domain for safe in safe_domains):
                    continue
            except Exception:
                pass

            filtered.append(url)

        return filtered[:5]  # Limit to 5 URLs to avoid rate limits

    def _detonate_urls(self, urls):
        """
        Detonate URLs via urlscan.io and return signals.

        Returns list of signals based on detonation results.
        """
        signals = []

        if not self.detonator or not urls:
            return signals

        detonation_results = []

        for url in urls:
            try:
                logger.info(f"Detonating URL: {url}")
                result = self.detonator.detonate(url)
                detonation_results.append(result)

                # Add signals based on classification
                classification = result.get('classification', '')

                if classification == 'HIGH_RISK':
                    signals.append({
                        'name': 'url_high_risk',
                        'description': f'URL detonation: HIGH RISK - {", ".join(result.get("risk_factors", [])[:2])}',
                        'weight': self.weights.get('url_high_risk', 30),
                        'evidence': {
                            'url': url,
                            'screenshot': result.get('evidence', {}).get('screenshot'),
                            'report': result.get('evidence', {}).get('report_url')
                        }
                    })
                elif classification == 'MEDIUM_RISK':
                    signals.append({
                        'name': 'url_medium_risk',
                        'description': f'URL detonation: MEDIUM RISK - {", ".join(result.get("risk_factors", [])[:2])}',
                        'weight': self.weights.get('url_medium_risk', 15),
                        'evidence': {
                            'url': url,
                            'screenshot': result.get('evidence', {}).get('screenshot'),
                            'report': result.get('evidence', {}).get('report_url')
                        }
                    })

                # Check for malicious verdict from urlscan
                if any('MALICIOUS' in f.upper() for f in result.get('risk_factors', [])):
                    signals.append({
                        'name': 'url_malicious',
                        'description': f'urlscan.io flagged URL as MALICIOUS: {url}',
                        'weight': self.weights.get('url_malicious', 40),
                        'evidence': {
                            'url': url,
                            'screenshot': result.get('evidence', {}).get('screenshot'),
                            'report': result.get('evidence', {}).get('report_url')
                        }
                    })

            except Exception as e:
                logger.error(f"URL detonation failed for {url}: {e}")
                # Don't add signal on failure - may just be rate limited

        return signals


# Singleton analyzer
_analyzer = None


def get_analyzer():
    """Get singleton analyzer instance."""
    global _analyzer
    if _analyzer is None:
        _analyzer = EmailAnalyzer()
    return _analyzer


def analyze_email(headers, body_html, sender, subject):
    """Convenience function to analyze an email."""
    return get_analyzer().analyze(headers, body_html, sender, subject)
