"""
Email Handler for PhishCheck

Handles:
1. Reading forwarded emails from phishing@forzon.ca via IMAP
2. Sending verdict replies via SMTP
"""

import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.header import decode_header
import logging
import time
import requests
from datetime import datetime

import config


def fetch_image_bytes(url, timeout=10):
    """Download image and return raw bytes for CID attachment."""
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            return response.content
    except Exception as e:
        logging.getLogger(__name__).warning(f'Failed to fetch image {url}: {e}')
    return None
from analyzer import analyze_email
from models import create_submission, find_or_create_campaign
from alerts import check_campaign_alerts

logger = logging.getLogger(__name__)


class EmailHandler:
    def __init__(self):
        self.imap_host = config.IMAP_HOST
        self.imap_port = config.IMAP_PORT
        self.smtp_host = config.SMTP_HOST
        self.smtp_port = config.SMTP_PORT
        self.email_user = config.EMAIL_USER
        self.email_pass = config.EMAIL_PASS

    def connect_imap(self):
        """Connect to IMAP server."""
        try:
            imap = imaplib.IMAP4_SSL(self.imap_host, self.imap_port)
            imap.login(self.email_user, self.email_pass)
            return imap
        except Exception as e:
            logger.error(f'IMAP connection failed: {e}')
            return None

    def get_unread_emails(self):
        """Fetch all emails from inbox (we delete after processing)."""
        imap = self.connect_imap()
        if not imap:
            return []

        emails = []
        try:
            imap.select('INBOX')
            _, message_ids = imap.search(None, 'ALL')

            for msg_id in message_ids[0].split():
                _, msg_data = imap.fetch(msg_id, '(RFC822)')
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                # Parse email
                parsed = self._parse_email(msg)
                parsed['imap_id'] = msg_id
                emails.append(parsed)

        except Exception as e:
            logger.error(f'Error fetching emails: {e}')
        finally:
            imap.logout()

        return emails

    def mark_as_read(self, imap_id):
        """Move email to Processed folder after handling."""
        imap = self.connect_imap()
        if not imap:
            return False

        try:
            imap.select('INBOX')

            # Create Processed folder if it doesn't exist
            imap.create('Processed')

            # Copy to Processed folder
            imap.copy(imap_id, 'Processed')

            # Delete from INBOX
            imap.store(imap_id, '+FLAGS', '\\Deleted')
            imap.expunge()
            return True
        except Exception as e:
            logger.error(f'Error moving email to Processed: {e}')
            return False
        finally:
            imap.logout()

    def _parse_email(self, msg):
        """Parse email message into structured data."""
        # Decode subject
        subject = ''
        if msg['Subject']:
            decoded = decode_header(msg['Subject'])
            subject = ''.join(
                part.decode(enc or 'utf-8') if isinstance(part, bytes) else part
                for part, enc in decoded
            )

        # Get sender
        sender = msg.get('From', '')

        # Get original sender if this is a forwarded email
        original_sender = sender
        original_subject = subject

        # Check for forwarded email patterns
        if subject.lower().startswith('fw:') or subject.lower().startswith('fwd:'):
            original_subject = subject[3:].strip() if subject.lower().startswith('fw:') else subject[4:].strip()

        # Get headers as string
        headers = ''
        for key, value in msg.items():
            headers += f'{key}: {value}\n'

        # Get body
        body_html = ''
        body_text = ''

        # Check for EML attachment first (best source of original email)
        eml_msg = None
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                filename = part.get_filename() or ''

                # Check for .eml attachment (message/rfc822)
                if content_type == 'message/rfc822' or filename.lower().endswith('.eml'):
                    # For message/rfc822, get_payload() returns a list of Message objects
                    payload = part.get_payload()
                    if isinstance(payload, list) and len(payload) > 0:
                        eml_msg = payload[0]
                    elif hasattr(payload, 'get'):  # Already a Message object
                        eml_msg = payload
                    break
                elif content_type == 'text/html':
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html = payload.decode('utf-8', errors='ignore')
                elif content_type == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text = payload.decode('utf-8', errors='ignore')
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                if msg.get_content_type() == 'text/html':
                    body_html = payload.decode('utf-8', errors='ignore')
                else:
                    body_text = payload.decode('utf-8', errors='ignore')

        # If we found an EML attachment, parse it for the original email
        if eml_msg:
            try:
                # Get original sender from EML
                original_sender = eml_msg.get('From', sender)

                # Get original subject from EML
                if eml_msg['Subject']:
                    decoded = decode_header(eml_msg['Subject'])
                    original_subject = ''.join(
                        part.decode(enc or 'utf-8') if isinstance(part, bytes) else part
                        for part, enc in decoded
                    )

                # Get original headers
                headers = ''
                for key, value in eml_msg.items():
                    headers += f'{key}: {value}\n'

                # Get body from EML
                if eml_msg.is_multipart():
                    for part in eml_msg.walk():
                        ct = part.get_content_type()
                        if ct == 'text/html':
                            p = part.get_payload(decode=True)
                            if p:
                                body_html = p.decode('utf-8', errors='ignore')
                        elif ct == 'text/plain' and not body_html:
                            p = part.get_payload(decode=True)
                            if p:
                                body_text = p.decode('utf-8', errors='ignore')
                else:
                    p = eml_msg.get_payload(decode=True)
                    if p:
                        if eml_msg.get_content_type() == 'text/html':
                            body_html = p.decode('utf-8', errors='ignore')
                        else:
                            body_text = p.decode('utf-8', errors='ignore')

                logger.info(f'Parsed EML attachment - Original sender: {original_sender}')
            except Exception as e:
                logger.warning(f'Failed to parse EML attachment: {e}')

        # Try to extract original email from forwarded content
        forwarded_headers, forwarded_body = self._extract_forwarded_email(body_html or body_text)

        return {
            'sender': sender,
            'subject': subject,
            'original_sender': forwarded_headers.get('from', original_sender),
            'original_subject': forwarded_headers.get('subject', original_subject),
            'headers': forwarded_headers.get('raw', headers),
            'body_html': forwarded_body or body_html or body_text,
            'reply_to': msg.get('Reply-To', sender)
        }

    def _extract_forwarded_email(self, body):
        """
        Try to extract the original email from a forwarded message.
        Handles both plain text and HTML forwarding from Gmail, O365, and other clients.

        Returns (headers_dict, body_content)
        """
        import re
        headers = {}
        original_body = ''

        if not body:
            return headers, original_body

        # Strip HTML tags for parsing (keep original for body)
        def strip_html(html):
            # Protect email addresses in angle brackets by temporarily replacing them
            # Match <email@domain.com> pattern
            email_pattern = r'<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>'
            protected = re.sub(email_pattern, r'[[EMAIL:\1]]', html)

            # Replace <br> and block elements with newlines
            text = re.sub(r'<br\s*/?\s*>', '\n', protected, flags=re.IGNORECASE)
            text = re.sub(r'</?(div|p|tr|td|li)[^>]*>', '\n', text, flags=re.IGNORECASE)
            # Remove all other tags
            text = re.sub(r'<[^>]+>', '', text)
            # Decode common entities
            text = text.replace('&nbsp;', ' ')
            text = text.replace('&lt;', '<')
            text = text.replace('&gt;', '>')
            text = text.replace('&amp;', '&')
            text = text.replace('&quot;', '"')
            # Restore email addresses
            text = re.sub(r'\[\[EMAIL:([^\]]+)\]\]', r'<\1>', text)
            return text

        # Only strip HTML if it looks like actual HTML (has tags like <html, <body, <div, etc.)
        is_html = bool(re.search(r'<(html|body|div|table|span|p)\b', body, re.IGNORECASE))
        text = strip_html(body) if is_html else body

        # Common forwarded email markers
        markers = [
            '---------- Forwarded message ---------',  # Gmail
            '-------- Original Message --------',      # O365
            '-----Original Message-----',              # Outlook
            'Begin forwarded message:',                # Apple Mail
            '________________________________',        # O365 separator
        ]

        # Also check for O365 HTML forward structure (divRplyFwdMsg)
        # This appears as "From:" followed by "Sent:" without a text marker
        has_o365_forward = 'divRplyFwdMsg' in body or bool(re.search(r'<b>From:</b>.*<b>Sent:</b>', body, re.DOTALL | re.IGNORECASE))

        lines = text.split('\n')
        in_headers = False
        header_start = -1

        for i, line in enumerate(lines):
            line_stripped = line.strip()

            # Check for forwarded message marker
            if not in_headers:
                for marker in markers:
                    if marker in line:
                        in_headers = True
                        header_start = i
                        break

                # O365 forward detection: look for "From:" followed by "Sent:" pattern
                # Check next few non-empty lines since HTML stripping can add blank lines
                if not in_headers and has_o365_forward:
                    if line_stripped.lower().startswith('from:'):
                        # Look ahead for Sent:/Date: in next 5 lines
                        for j in range(i + 1, min(i + 6, len(lines))):
                            next_line = lines[j].strip().lower()
                            if next_line.startswith('sent:') or next_line.startswith('date:'):
                                in_headers = True
                                header_start = i
                                break
                            elif next_line and not next_line.startswith(('to:', 'cc:', 'bcc:')):
                                # Non-empty line that's not a header - stop looking
                                break

            if in_headers and header_start >= 0:
                # Parse forwarded headers - handle various formats
                # Gmail: "From: Name <email@domain.com>"
                # O365: "From: Name [mailto:email@domain.com]"

                line_lower = line_stripped.lower()

                if line_lower.startswith('from:'):
                    from_value = line_stripped[5:].strip()
                    # Clean up mailto: format
                    from_value = re.sub(r'\[mailto:([^\]]+)\]', r'<\1>', from_value)
                    headers['from'] = from_value
                elif line_lower.startswith('sent:') or line_lower.startswith('date:'):
                    headers['date'] = re.sub(r'^(sent|date):\s*', '', line_stripped, flags=re.IGNORECASE)
                elif line_lower.startswith('subject:'):
                    headers['subject'] = line_stripped[8:].strip()
                elif line_lower.startswith('to:'):
                    headers['to'] = line_stripped[3:].strip()
                elif line_lower.startswith('reply-to:'):
                    headers['reply-to'] = line_stripped[9:].strip()
                elif line_stripped == '' and headers.get('from'):
                    # End of headers (blank line after we have From), rest is body
                    original_body = '\n'.join(lines[i+1:])
                    break

        # If we found headers, build raw header string
        if headers:
            headers['raw'] = '\n'.join(f'{k}: {v}' for k, v in headers.items() if k != 'raw')
            logger.info(f'Extracted forwarded email - From: {headers.get("from", "unknown")}')

        return headers, original_body

    def send_verdict_reply(self, to_email, original_subject, result, submission_id, analyzed_sender=None, analyzed_subject=None):
        """Send verdict email reply."""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f'RE: {original_subject}'
            msg['From'] = f'"PhishCheck" <{self.email_user}>'
            msg['To'] = to_email

            # Build verdict email
            verdict_upper = result['verdict'].upper()
            raw_score = result['confidence']
            sender_domain = result.get('sender_domain', '')

            # For safe emails, show confidence it's safe (inverted)
            # For phishing/suspicious, show confidence it's risky
            if result['verdict'] == 'safe':
                confidence = 100 - raw_score  # 10 risk = 90% safe
            else:
                confidence = raw_score  # 70 risk = 70% phishing

            if result['verdict'] == 'phishing':
                emoji = '🔴'
                verdict_text = 'YES - THIS IS PHISHING'
                confidence_label = f'{confidence}% confident this is phishing'
                action = 'Delete this email immediately. Do not click any links or download attachments.'
                bg_color = '#FEE2E2'
                text_color = '#991B1B'
                header_border = '#DC2626'
            elif result['verdict'] == 'suspicious':
                emoji = '🟡'
                verdict_text = 'SUSPICIOUS'
                confidence_label = f'{confidence}% risk level'
                action = 'Exercise caution. Verify the sender through another channel before taking action.'
                bg_color = '#FEF3C7'
                text_color = '#92400E'
                header_border = '#F59E0B'
            else:
                emoji = '🟢'
                verdict_text = 'LIKELY SAFE'
                confidence_label = f'{confidence}% confident this is safe'
                action = 'This email appears legitimate, but always stay vigilant.'
                bg_color = '#D1FAE5'
                text_color = '#065F46'
                header_border = '#10B981'

            # Build detailed signals list with explanations
            signals_html = ''
            for signal in result.get('signals', []):
                weight = signal.get('weight', 0)
                severity = 'high' if weight >= 15 else 'medium' if weight >= 10 else 'low'
                color = '#DC2626' if severity == 'high' else '#F59E0B' if severity == 'medium' else '#6B7280'
                signals_html += f'''
                <tr>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #E5E7EB;">
                        <span style="color: {color}; font-weight: bold;">{"⚠️" if severity == "high" else "⚡" if severity == "medium" else "ℹ️"}</span>
                        {signal["description"]}
                    </td>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #E5E7EB; text-align: right; color: {color}; font-weight: bold;">
                        +{weight}
                    </td>
                </tr>'''

            feedback_url = f'https://phishcheck.forzon.ca/feedback/{submission_id}'

            # Extract detonation evidence from signals
            detonation_results = []
            for signal in result.get('signals', []):
                evidence = signal.get('evidence', {})
                if evidence.get('screenshot') or evidence.get('report'):
                    detonation_results.append({
                        'url': evidence.get('url', 'Unknown URL'),
                        'screenshot': evidence.get('screenshot'),
                        'report': evidence.get('report')
                    })

            # Build detonation section HTML with CID-attached images
            detonation_html = ''
            detonation_text = ''
            screenshot_attachments = []  # List of (cid, image_bytes) tuples
            if detonation_results:
                detonation_html = '''
                <div style="background: #EFF6FF; padding: 20px; border-bottom: 1px solid #BFDBFE;">
                    <h3 style="margin: 0 0 15px 0; color: #1E40AF; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">🔍 URL Detonation Results</h3>
                '''
                for i, det in enumerate(detonation_results[:3]):  # Limit to 3
                    short_url = det['url'][:60] + '...' if len(det['url']) > 60 else det['url']

                    # Fetch screenshot for CID attachment
                    screenshot_html = ''
                    if det.get('screenshot'):
                        img_bytes = fetch_image_bytes(det['screenshot'])
                        if img_bytes:
                            cid = f'screenshot_{i}'
                            screenshot_attachments.append((cid, img_bytes))
                            screenshot_html = f'<img src="cid:{cid}" style="max-width: 280px; max-height: 180px; border: 1px solid #E5E7EB; border-radius: 4px;" alt="Screenshot of {short_url}">'
                        else:
                            # Fallback to external URL link
                            screenshot_html = f'<a href="{det["screenshot"]}" style="color: #2563EB;">View Screenshot</a>'

                    detonation_html += f'''
                    <div style="background: white; border: 1px solid #BFDBFE; border-radius: 8px; padding: 15px; margin-bottom: 10px;">
                        <p style="margin: 0 0 10px 0; font-size: 12px; color: #6B7280; word-break: break-all;"><strong>URL {i+1}:</strong> {short_url}</p>
                        {screenshot_html}
                        {f'<p style="margin: 10px 0 0 0;"><a href="{det["report"]}" style="color: #2563EB; text-decoration: none; font-size: 13px;">📄 View Full Report on urlscan.io →</a></p>' if det.get('report') else ''}
                    </div>
                    '''
                detonation_html += '</div>'

                detonation_text = '\nURL DETONATION RESULTS:\n'
                for i, det in enumerate(detonation_results[:3]):
                    detonation_text += f'  URL {i+1}: {det["url"][:80]}\n'
                    if det.get('screenshot'):
                        detonation_text += f'    Screenshot: {det["screenshot"]}\n'
                    if det.get('report'):
                        detonation_text += f'    Report: {det["report"]}\n'

            # Escape HTML in sender/subject
            safe_sender = (analyzed_sender or '').replace('<', '&lt;').replace('>', '&gt;')
            safe_subject = (analyzed_subject or original_subject or '').replace('<', '&lt;').replace('>', '&gt;')

            html = f'''
            <div style="font-family: Arial, sans-serif; max-width: 650px; margin: 0 auto; border: 2px solid {header_border}; border-radius: 12px; overflow: hidden;">
                <div style="background: {bg_color}; padding: 25px; text-align: center;">
                    <div style="font-size: 56px;">{emoji}</div>
                    <h1 style="color: {text_color}; margin: 10px 0; font-size: 28px;">{verdict_text}</h1>
                    <div style="background: white; display: inline-block; padding: 8px 20px; border-radius: 20px; margin-top: 5px;">
                        <span style="color: {text_color}; font-size: 18px; font-weight: bold;">{confidence_label}</span>
                    </div>
                </div>

                <div style="background: #F9FAFB; padding: 20px; border-bottom: 1px solid #E5E7EB;">
                    <h3 style="margin: 0 0 15px 0; color: #111827; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">Email Analyzed</h3>
                    <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; border: 1px solid #E5E7EB;">
                        <tr>
                            <td style="padding: 10px 15px; background: #F3F4F6; font-weight: bold; width: 80px; color: #374151;">From:</td>
                            <td style="padding: 10px 15px; color: #111827; word-break: break-all;"><code style="background: #FEE2E2; padding: 2px 6px; border-radius: 4px;">{safe_sender}</code></td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 15px; background: #F3F4F6; font-weight: bold; color: #374151;">Subject:</td>
                            <td style="padding: 10px 15px; color: #111827;">{safe_subject or '<em style="color: #9CA3AF;">No subject</em>'}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 15px; background: #F3F4F6; font-weight: bold; color: #374151;">Domain:</td>
                            <td style="padding: 10px 15px; color: #111827;"><code style="background: #E5E7EB; padding: 2px 6px; border-radius: 4px;">{sender_domain or 'Unknown'}</code></td>
                        </tr>
                    </table>
                </div>

                <div style="background: white; padding: 20px;">
                    <h3 style="margin: 0 0 15px 0; color: #111827; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">Risk Signals Detected ({len(result.get('signals', []))})</h3>
                    {f'<table style="width: 100%; border-collapse: collapse; border: 1px solid #E5E7EB; border-radius: 8px; overflow: hidden;">{signals_html}</table>' if signals_html else '<p style="color: #6B7280; text-align: center; padding: 20px;">No specific risk signals detected</p>'}

                    <div style="background: {bg_color}; border: 1px solid {header_border}; border-radius: 8px; padding: 15px; margin-top: 20px;">
                        <strong style="color: {text_color};">📋 Recommended Action:</strong>
                        <p style="color: #374151; margin: 10px 0 0 0;">{action}</p>
                    </div>
                </div>

                {detonation_html}

                <div style="background: #F3F4F6; padding: 20px; text-align: center;">
                    <p style="margin: 0 0 15px 0; color: #374151; font-weight: bold;">Was this verdict helpful?</p>
                    <a href="{feedback_url}?correct=yes" style="display: inline-block; padding: 12px 24px; background: #10B981; color: white; text-decoration: none; border-radius: 6px; margin: 0 8px; font-weight: bold;">👍 Correct</a>
                    <a href="{feedback_url}?correct=no" style="display: inline-block; padding: 12px 24px; background: #EF4444; color: white; text-decoration: none; border-radius: 6px; margin: 0 8px; font-weight: bold;">👎 Incorrect</a>
                </div>

                <div style="background: #1F2937; padding: 15px; text-align: center;">
                    <p style="color: #9CA3AF; font-size: 12px; margin: 0;">
                        PhishCheck - Internal Phishing Detection Tool<br>
                        <span style="color: #6B7280;">Submission ID: {submission_id[:8]}...</span>
                    </p>
                </div>
            </div>
            '''

            text = f'''
{'='*50}
{verdict_text}
{confidence_label}
{'='*50}

EMAIL ANALYZED:
  From: {analyzed_sender or 'Unknown'}
  Subject: {analyzed_subject or original_subject or 'No subject'}
  Domain: {sender_domain or 'Unknown'}

RISK SIGNALS DETECTED ({len(result.get('signals', []))}):
{chr(10).join('  [+' + str(s['weight']) + '] ' + s['description'] for s in result.get('signals', [])) or '  No specific risk signals detected'}

RECOMMENDED ACTION:
{action}
{detonation_text}
{'='*50}
Was this verdict correct?
  Yes: {feedback_url}?correct=yes
  No:  {feedback_url}?correct=no
{'='*50}
PhishCheck - Submission ID: {submission_id}
'''

            msg.attach(MIMEText(text, 'plain'))

            # If we have screenshot attachments, use related MIME structure
            if screenshot_attachments:
                # Create a related part for HTML + inline images
                html_related = MIMEMultipart('related')
                html_related.attach(MIMEText(html, 'html'))

                # Attach each screenshot with CID
                for cid, img_bytes in screenshot_attachments:
                    img = MIMEImage(img_bytes)
                    img.add_header('Content-ID', f'<{cid}>')
                    img.add_header('Content-Disposition', 'inline', filename=f'{cid}.png')
                    html_related.attach(img)

                msg.attach(html_related)
            else:
                msg.attach(MIMEText(html, 'html'))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.email_user, self.email_pass)
                server.sendmail(self.email_user, to_email, msg.as_string())

            logger.info(f'Verdict email sent to {to_email}')
            return True

        except Exception as e:
            logger.error(f'Failed to send verdict email: {e}')
            return False

    def process_inbox(self):
        """
        Process all unread emails in the inbox.

        This should be called periodically (e.g., every 30 seconds).
        """
        emails = self.get_unread_emails()
        processed = 0

        for email_data in emails:
            try:
                # Analyze the forwarded email
                result = analyze_email(
                    headers=email_data['headers'],
                    body_html=email_data['body_html'],
                    sender=email_data['original_sender'],
                    subject=email_data['original_subject']
                )

                # Get submitter email (the person who forwarded)
                submitter = email_data['reply_to'] or email_data['sender']
                # Extract just the email address
                if '<' in submitter:
                    submitter = submitter.split('<')[1].split('>')[0]

                # Link to campaign
                campaign, is_new = find_or_create_campaign(
                    fingerprint=result['fingerprint'],
                    sender_domain=result['sender_domain'],
                    subject=email_data['original_subject'][:100] if email_data['original_subject'] else ''
                )
                campaign_id = campaign['id'] if campaign else None

                # Create submission (returns string ID)
                submission_id = create_submission(
                    fingerprint=result['fingerprint'],
                    submitted_by=submitter,
                    submission_method='forward',
                    department=None,  # Could look up via Graph API later
                    original_sender=email_data['original_sender'],
                    sender_domain=result['sender_domain'],
                    subject=email_data['original_subject'],
                    headers=email_data['headers'],
                    body_html=email_data['body_html'],
                    verdict=result['verdict'],
                    confidence=result['confidence'],
                    signals=result['signals'],
                    campaign_id=campaign_id
                )

                # Check for CISO alert
                if campaign and config.ENABLE_CISO_ALERTS:
                    try:
                        check_campaign_alerts(
                            campaign['id'],
                            campaign['name'],
                            campaign['user_count'],
                            {'sender_domain': result['sender_domain'], 'subject_pattern': email_data['original_subject']}
                        )
                    except Exception as e:
                        logger.warning(f'Failed to check campaign alerts: {e}')

                # Send reply
                self.send_verdict_reply(
                    to_email=submitter,
                    original_subject=email_data['subject'],
                    result=result,
                    submission_id=submission_id,
                    analyzed_sender=email_data['original_sender'],
                    analyzed_subject=email_data['original_subject']
                )

                # Mark as read
                self.mark_as_read(email_data['imap_id'])
                processed += 1

            except Exception as e:
                logger.error(f'Error processing email: {e}')

        return processed


# Singleton
_handler = None


def get_email_handler():
    global _handler
    if _handler is None:
        _handler = EmailHandler()
    return _handler


def process_inbox():
    """Convenience function to process inbox."""
    return get_email_handler().process_inbox()
