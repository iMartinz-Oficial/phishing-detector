"""Test VirusTotal API"""

import requests
import urllib.parse
import json

VIRUSTOTAL_API_KEY = "95fb73b2aacb4c03eef468de781c8360a183c96745c52d92e6a9c66fb46a0f06"
url = "https://www.facebook.com"

encoded_url = urllib.parse.quote(url, safe="")
response = requests.get(
    f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
    headers={"x-apikey": VIRUSTOTAL_API_KEY},
    timeout=10,
)

print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")
