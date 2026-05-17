"""Test VirusTotal API - try submit"""

import requests
import urllib.parse
import json

VIRUSTOTAL_API_KEY = "95fb73b2aacb4c03eef468de781c8360a183c96745c52d92e6a9c66fb46a0f06"
url = "https://www.facebook.com"

# Try to submit URL for analysis
response = requests.post(
    "https://www.virustotal.com/api/v3/urls",
    headers={
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
    },
    data=f"url={urllib.parse.quote(url)}",
    timeout=10,
)

print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")
