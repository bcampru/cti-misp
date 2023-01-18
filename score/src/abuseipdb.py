import os
import json
from urllib.error import HTTPError

import requests

class AbuseIPDB:
    _SOURCE_NAME = "AbuseIPDB"
    def __init__(self):
        # Instantiate the connector helper from config
        self.name="AbuseIPDB"
        self.api_key = os.getenv('ABUSEIPDB_API_KEY')

    @staticmethod
    def extract_abuse_ipdb_category(category_number):
        # Reference: https://www.abuseipdb.com/categories
        mapping = {
            "3": "Fraud Orders",
            "4": "DDOS Attack",
            "5": "FTP Brute-Force",
            "6": "Ping of Death",
            "7": "Phishing",
            "8": "Fraud VOIP",
            "9": "Open Proxy",
            "10": "Web Spam",
            "11": "Email Spam",
            "12": "Blog Spam",
            "13": "VPN IP",
            "14": "Port Scan",
            "15": "Hacking",
            "16": "SQL Injection",
            "17": "Spoofing",
            "18": "Brute Force",
            "19": "Bad Web Bot",
            "20": "Exploited Host",
            "21": "Web App Attack",
            "22": "SSH",
            "23": "IoT Targeted",
        }
        return mapping.get(str(category_number), "unknown category")

    def _process_message(self, ip, callback):
        # Extract IP from entity data
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "Key": "%s" % self.api_key,
            }
            params = {"maxAgeInDays": 365, "verbose": "True", "ipAddress": ip['value']}
            r = requests.get(url, headers=headers, params=params)
            r.raise_for_status()
            data = r.json()
            data = data["data"]
            if data["isWhitelisted"]:
                callback(ip, 0)
                return
            if len(data["reports"]) > 0:
                found = []
                for report in data["reports"]:
                    for category in report["categories"]:
                        if category not in found:
                            found.append(category)
                            category_text = self.extract_abuse_ipdb_category(category)
            print("va")
            callback(ip, data["abuseConfidenceScore"], self._SOURCE_NAME)
        except Exception as e:
            print(e.response.json()["errors"][0]["detail"])
            if (e.response.json()["errors"][0]["status"]==429):
                callback(ip, -1, self._SOURCE_NAME)
