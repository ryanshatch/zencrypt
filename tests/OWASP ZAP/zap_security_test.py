"""
********************************************************************************************
* Title: Zencrypt WebApp           |********************************************************
* Developed by: Ryan Hatch         |********************************************************
* Date: August 10th 2022           |********************************************************
* Last Updated: Febuary 13th 2025  |********************************************************
* Version: 6.2-A                   |********************************************************
********************************************************************************************
*****************************#*| Zencrypt v6.2-A |******************************************
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
********************************#* Description: |*******************************************
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
*              Zencrypt Web-App is a Flask application that can be used to:                *
*       - Generate hashes: using SHA256 hashing algorithm, with an optional salt value.    *
*       - Encrypt text and files: using Fernet symmetric encryption algorithm.             *
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
"""

import unittest
from zapv2 import ZAPv2
import json
import time

class ZencryptSecurityTests(unittest.TestCase):
    def setUp(self):
        # Initialize ZAP API client
        self.zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        self.target = 'http://localhost:5000'
        
    def test_authentication_endpoints(self):
        # Test login endpoint
        self.zap.urlopen(f"{self.target}/login")
        time.sleep(2)
        alerts = self.zap.core.alerts()
        self.document_findings('authentication', alerts)
        
        # Test registration endpoint
        self.zap.urlopen(f"{self.target}/register")
        time.sleep(2)
        alerts = self.zap.core.alerts()
        self.document_findings('registration', alerts)

    def test_key_management(self):
        # Test key export/import
        self.zap.urlopen(f"{self.target}/export-key")
        self.zap.urlopen(f"{self.target}/import-key")
        time.sleep(2)
        alerts = self.zap.core.alerts()
        self.document_findings('key_management', alerts)

    def test_file_operations(self):
        # Test file upload endpoints
        self.zap.urlopen(f"{self.target}/file")
        time.sleep(2)
        alerts = self.zap.core.alerts()
        self.document_findings('file_operations', alerts)

    def document_findings(self, test_area, alerts):
        findings = {
            'test_area': test_area,
            'high_risks': [],
            'medium_risks': [],
            'low_risks': []
        }
        
        for alert in alerts:
            if alert['risk'] == 'High':
                findings['high_risks'].append({
                    'title': alert['name'],
                    'description': alert['description'],
                    'mitigation': self.get_mitigation(alert['name'])
                })
            elif alert['risk'] == 'Medium':
                findings['medium_risks'].append({
                    'title': alert['name'],
                    'description': alert['description'],
                    'mitigation': self.get_mitigation(alert['name'])
                })
            elif alert['risk'] == 'Low':
                findings['low_risks'].append({
                    'title': alert['name'],
                    'description': alert['description'],
                    'mitigation': self.get_mitigation(alert['name'])
                })
                
        with open(f'security_findings_{test_area}.json', 'w') as f:
            json.dump(findings, f, indent=4)

    def get_mitigation(self, alert_name):
        mitigations = {
            'SQL Injection': 'Use parameterized queries and input validation',
            'XSS': 'Implement Content Security Policy headers and escape output',
            'Insecure File Upload': 'Validate file types, implement size limits',
            'Authentication Bypass': 'Implement rate limiting and strong password policies',
            'Sensitive Data Exposure': 'Ensure proper encryption of sensitive data'
        }
        return mitigations.get(alert_name, 'Review security best practices')

if __name__ == '__main__':
    unittest.main()