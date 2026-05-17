"""Test with different URL encoding"""

import requests
import urllib.parse
import json
import base64

VIRUSTOTAL_API_KEY = "95fb73b2aacb4c03eef468de781c8360a183c96745c52d92e6a9c66fb46a0f06"

# Try different methods
test_urls = [
    "http://apple-verify-account.xyz/login",
    "https://www.facebook.com",
    "http://secure-paypal-verify.xyz/login",
]

for url in test_urls:
    print(f"\n--- Testing: {url} ---")

    # Method 1: Base64 encoded URL id
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
        timeout=10,
    )

    print(f"Method 1 (base64): Status {response.status_code}")

    # Method 2: URL encoded
    response2 = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{urllib.parse.quote(url, safe='')}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
        timeout=10,
    )

    print(f"Method 2 (url encoded): Status {response2.status_code}")

    # Method 3: just the domain
    if "://" in url:
        domain = url.split("://")[1].split("/")[0]
        response3 = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        print(f"Method 3 (domain): Status {response3.status_code}")

        if response3.status_code == 200:
            data = response3.json()
            last_analysis_stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            print(f"  Domain stats: {last_analysis_stats}")
