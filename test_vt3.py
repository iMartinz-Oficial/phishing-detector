"""Test with a known phishing URL"""

import requests
import urllib.parse
import json

VIRUSTOTAL_API_KEY = "95fb73b2aacb4c03eef468de781c8360a183c96745c52d92e6a9c66fb46a0f06"
url = "http://apple-verify-account.xyz/login"

encoded_url = urllib.parse.quote(url, safe="")
response = requests.get(
    f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
    headers={"x-apikey": VIRUSTOTAL_API_KEY},
    timeout=10,
)

print(f"Status: {response.status_code}")
if response.status_code == 200:
    data = response.json()
    last_analysis = (
        data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    )

    malicious = 0
    suspicious = 0
    harmless = 0
    undetected = 0
    phishing_count = 0

    for engine, result in last_analysis.items():
        category = result.get("category", "")
        result_name = result.get("result", "")
        if category == "malicious" or result_name == "phishing":
            malicious += 1
            if result_name == "phishing":
                phishing_count += 1
        elif category == "suspicious":
            suspicious += 1
        elif category == "harmless":
            harmless += 1
        else:
            undetected += 1

    total = malicious + suspicious + harmless + undetected
    print(f"Total: {total}")
    print(f"Malicious: {malicious}")
    print(f"Suspicious: {suspicious}")
    print(f"Phishing: {phishing_count}")
    print(f"Harmless: {harmless}")
    print(f"Undetected: {undetected}")
else:
    print(f"Error: {response.text}")
