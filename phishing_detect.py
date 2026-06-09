#!/usr/bin/env python3
"""
Simple Phishing Detection Tool
Checks URLs for common phishing indicators
"""

import re
import urllib.parse
from typing import List, Dict, Tuple

class PhishingDetector:
    def __init__(self):
        # Common phishing indicators
        self.suspicious_keywords = [
            'secure', 'verify', 'update', 'confirm', 'login', 'account',
            'suspended', 'limited', 'urgent', 'immediate', 'click',
            'banking', 'paypal', 'amazon', 'microsoft', 'google'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'short.link',
            'click.email', 'email.click'
        ]
        
        self.legitimate_domains = [
            'google.com', 'microsoft.com', 'amazon.com', 'paypal.com',
            'facebook.com', 'twitter.com', 'github.com', 'stackoverflow.com'
        ]

    def analyze_url(self, url: str) -> Dict:
        """Analyze a URL for phishing indicators"""
        result = {
            'url': url,
            'risk_score': 0,
            'indicators': [],
            'risk_level': 'LOW'
        }
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check for suspicious domain patterns
            if self._has_suspicious_domain(domain):
                result['risk_score'] += 30
                result['indicators'].append('Suspicious domain detected')
            
            # Check for URL shorteners
            if self._is_url_shortener(domain):
                result['risk_score'] += 20
                result['indicators'].append('URL shortener detected')
            
            # Check for suspicious keywords
            suspicious_words = self._check_suspicious_keywords(url.lower())
            if suspicious_words:
                result['risk_score'] += len(suspicious_words) * 5
                result['indicators'].append(f'Suspicious keywords: {", ".join(suspicious_words)}')
            
            # Check for IP address instead of domain
            if self._is_ip_address(domain):
                result['risk_score'] += 25
                result['indicators'].append('IP address used instead of domain')
            
            # Check URL length
            if len(url) > 100:
                result['risk_score'] += 10
                result['indicators'].append('Unusually long URL')
            
            # Check for excessive subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                result['risk_score'] += 15
                result['indicators'].append('Excessive subdomains')
            
            # Determine risk level
            if result['risk_score'] >= 50:
                result['risk_level'] = 'HIGH'
            elif result['risk_score'] >= 25:
                result['risk_level'] = 'MEDIUM'
            
        except Exception as e:
            result['indicators'].append(f'Error parsing URL: {str(e)}')
            result['risk_score'] = 100
            result['risk_level'] = 'HIGH'
        
        return result

    def _has_suspicious_domain(self, domain: str) -> bool:
        """Check if domain contains suspicious patterns"""
        # Check for typosquatting of legitimate domains
        for legit_domain in self.legitimate_domains:
            if self._is_typosquatting(domain, legit_domain):
                return True
        return False

    def _is_typosquatting(self, domain: str, legitimate: str) -> bool:
        """Simple typosquatting detection"""
        if legitimate in domain and domain != legitimate:
            return True
        
        # Check for character substitution (e.g., googIe.com)
        if len(domain) == len(legitimate):
            diff_count = sum(1 for a, b in zip(domain, legitimate) if a != b)
            if 1 <= diff_count <= 2:
                return True
        
        return False

    def _is_url_shortener(self, domain: str) -> bool:
        """Check if domain is a known URL shortener"""
        return any(shortener in domain for shortener in self.suspicious_domains)

    def _check_suspicious_keywords(self, url: str) -> List[str]:
        """Find suspicious keywords in URL"""
        found_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in url:
                found_keywords.append(keyword)
        return found_keywords

    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.match(ip_pattern, domain))

def main():
    detector = PhishingDetector()
    
    print("=== Simple Phishing Detection Tool ===")
    print("Enter URLs to analyze (type 'quit' to exit)")
    print()
    
    while True:
        url = input("Enter URL: ").strip()
        
        if url.lower() == 'quit':
            break
        
        if not url:
            continue
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        result = detector.analyze_url(url)
        
        print(f"\n--- Analysis Results ---")
        print(f"URL: {result['url']}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Risk Score: {result['risk_score']}/100")
        
        if result['indicators']:
            print("Indicators:")
            for indicator in result['indicators']:
                print(f"  • {indicator}")
        else:
            print("No suspicious indicators found")
        
        print("-" * 40)

if __name__ == "__main__":
    main()