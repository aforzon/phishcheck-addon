#!/usr/bin/env python3
"""
URL Detonation via urlscan.io API
Your IP never touches the phishing site
"""

import requests
import time
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class URLScanDetonator:

    BASE_URL = "https://urlscan.io/api/v1"

    BRAND_KEYWORDS = [
        'microsoft', 'office', 'outlook', 'onedrive', 'sharepoint',
        'google', 'gmail', 'drive', 'apple', 'icloud',
        'amazon', 'aws', 'paypal', 'bank', 'secure', 'verify'
    ]

    def __init__(self, api_key: str, output_dir: str = "./detonations"):
        self.api_key = api_key
        self.headers = {"API-Key": api_key}
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def submit_scan(self, url: str, visibility: str = "unlisted") -> dict:
        """
        Submit URL for scanning.
        visibility: 'public', 'unlisted', or 'private'
        """
        resp = requests.post(
            f"{self.BASE_URL}/scan/",
            headers=self.headers,
            json={"url": url, "visibility": visibility}
        )

        if resp.status_code == 429:
            raise Exception("Rate limited - urlscan.io free tier is 50/day")

        resp.raise_for_status()
        return resp.json()

    def get_result(self, uuid: str, max_wait: int = 60) -> dict:
        """
        Poll for scan results. Scans typically complete in 10-30 seconds.
        """
        result_url = f"{self.BASE_URL}/result/{uuid}/"

        for _ in range(max_wait // 5):
            resp = requests.get(result_url)
            if resp.status_code == 200:
                return resp.json()
            time.sleep(5)

        raise Exception(f"Scan {uuid} did not complete within {max_wait}s")

    def analyze(self, scan_result: dict) -> dict:
        """
        Analyze urlscan.io results and calculate risk score.
        """
        result = {
            "original_url": scan_result.get("task", {}).get("url"),
            "timestamp": datetime.now().isoformat(),
            "risk_score": 0,
            "risk_factors": [],
            "evidence": {}
        }

        page = scan_result.get("page", {})
        lists = scan_result.get("lists", {})
        verdicts = scan_result.get("verdicts", {})

        # Basic evidence
        result["evidence"]["final_url"] = page.get("url")
        result["evidence"]["title"] = page.get("title")
        result["evidence"]["domain"] = page.get("domain")
        result["evidence"]["ip"] = page.get("ip")
        result["evidence"]["country"] = page.get("country")
        result["evidence"]["screenshot"] = scan_result.get("task", {}).get("screenshotURL")
        result["evidence"]["report_url"] = scan_result.get("task", {}).get("reportURL")

        # Check urlscan.io verdicts
        overall = verdicts.get("overall", {})
        if overall.get("malicious"):
            result["risk_factors"].append("urlscan.io flagged as MALICIOUS")
            result["risk_score"] += 50
        if overall.get("score", 0) > 0:
            result["risk_factors"].append(f"urlscan.io threat score: {overall.get('score')}")
            result["risk_score"] += overall.get("score", 0) * 5

        # Check for redirects
        if page.get("url") != result["original_url"]:
            result["risk_factors"].append(f"Redirected to: {page.get('url')}")
            result["risk_score"] += 15

        # Check detected technologies for login forms
        if "login" in str(lists.get("urls", [])).lower():
            result["risk_factors"].append("Login-related URLs detected")
            result["risk_score"] += 20

        # Brand impersonation check
        page_text = str(page.get("title", "")).lower() + str(lists).lower()
        detected_brands = [b for b in self.BRAND_KEYWORDS if b in page_text]

        if detected_brands:
            result["evidence"]["detected_brands"] = detected_brands
            domain = page.get("domain", "").lower()

            for brand in detected_brands:
                if brand in ['microsoft', 'office', 'outlook']:
                    if 'microsoft.com' not in domain and 'office.com' not in domain:
                        result["risk_factors"].append(f"Possible {brand} impersonation")
                        result["risk_score"] += 35
                        break
                elif brand == 'google' and 'google.com' not in domain:
                    result["risk_factors"].append("Possible Google impersonation")
                    result["risk_score"] += 35
                    break
                elif brand == 'paypal' and 'paypal.com' not in domain:
                    result["risk_factors"].append("Possible PayPal impersonation")
                    result["risk_score"] += 35
                    break
                elif brand == 'amazon' and 'amazon.com' not in domain:
                    result["risk_factors"].append("Possible Amazon impersonation")
                    result["risk_score"] += 35
                    break

        # Check if on known bad lists
        if lists.get("ips"):
            result["evidence"]["ips_contacted"] = lists["ips"][:10]

        # SSL check
        if not str(page.get("url", "")).startswith("https"):
            result["risk_factors"].append("No HTTPS")
            result["risk_score"] += 15

        # Classification
        if result["risk_score"] >= 70:
            result["classification"] = "HIGH_RISK"
        elif result["risk_score"] >= 40:
            result["classification"] = "MEDIUM_RISK"
        elif result["risk_score"] >= 20:
            result["classification"] = "LOW_RISK"
        else:
            result["classification"] = "LIKELY_SAFE"

        return result

    def detonate(self, url: str, visibility: str = "unlisted") -> dict:
        """
        Full detonation: submit, wait, analyze.
        """
        logger.info(f"Submitting to urlscan.io: {url}")
        submission = self.submit_scan(url, visibility)
        uuid = submission["uuid"]
        logger.info(f"Scan UUID: {uuid}")

        raw_result = self.get_result(uuid)
        analysis = self.analyze(raw_result)

        # Save full report
        report_path = self.output_dir / f"{uuid}.json"
        with open(report_path, 'w') as f:
            json.dump({"analysis": analysis, "raw": raw_result}, f, indent=2, default=str)
        analysis["evidence"]["local_report"] = str(report_path)

        logger.info(f"Detonation complete: {analysis['classification']} (score: {analysis['risk_score']})")
        return analysis

    def detonate_batch(self, urls: list, visibility: str = "unlisted") -> list:
        """
        Batch scan with rate limiting (urlscan allows ~1/sec)
        """
        results = []

        for url in urls:
            try:
                result = self.detonate(url, visibility)
                results.append(result)
                time.sleep(2)  # Be nice to the API
            except Exception as e:
                logger.error(f"Failed to detonate {url}: {e}")
                results.append({"url": url, "error": str(e), "classification": "SCAN_FAILED"})

        return results


def main():
    import sys
    import os

    api_key = os.environ.get("URLSCAN_API_KEY")
    if not api_key:
        print("Set URLSCAN_API_KEY environment variable")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: python urlscan_detonator.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    detonator = URLScanDetonator(api_key)
    result = detonator.detonate(url)

    print(f"\n{'='*60}")
    print(f"Classification: {result['classification']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"{'='*60}")

    if result['risk_factors']:
        print("\nRisk Factors:")
        for factor in result['risk_factors']:
            print(f"  - {factor}")

    print(f"\nScreenshot: {result['evidence'].get('screenshot', 'N/A')}")
    print(f"Full Report: {result['evidence'].get('report_url', 'N/A')}")


if __name__ == "__main__":
    main()
