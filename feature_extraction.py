import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests
import tldextract

def extract_features(url, get_html=False):
    """
    Extract all 48 features matching your dataset
    Set get_html=True only during training with HTML access
    For real-time detection, set get_html=False (will use default values)
    """
    features = {}
    
    try:
        # Parse URL
        parsed = urlparse(url)
        domain_info = tldextract.extract(url)
        path = parsed.path
        query = parsed.query
        
        # 1. NumDots
        features["NumDots"] = url.count(".")
        
        # 2. SubdomainLevel
        features["SubdomainLevel"] = len(domain_info.subdomain.split('.')) if domain_info.subdomain else 0
        
        # 3. PathLevel
        features["PathLevel"] = len([p for p in path.split('/') if p]) if path else 0
        
        # 4. UrlLength
        features["UrlLength"] = len(url)
        
        # 5. NumDash
        features["NumDash"] = url.count("-")
        
        # 6. NumDashInHostname
        features["NumDashInHostname"] = parsed.netloc.count("-")
        
        # 7. AtSymbol
        features["AtSymbol"] = 1 if "@" in url else 0
        
        # 8. TildeSymbol
        features["TildeSymbol"] = 1 if "~" in url else 0
        
        # 9. NumUnderscore
        features["NumUnderscore"] = url.count("_")
        
        # 10. NumPercent
        features["NumPercent"] = url.count("%")
        
        # 11. NumQueryComponents
        features["NumQueryComponents"] = len(query.split("&")) if query else 0
        
        # 12. NumAmpersand
        features["NumAmpersand"] = url.count("&")
        
        # 13. NumHash
        features["NumHash"] = url.count("#")
        
        # 14. NumNumericChars
        features["NumNumericChars"] = sum(c.isdigit() for c in parsed.netloc)
        
        # 15. NoHttps
        features["NoHttps"] = 0 if url.startswith("https") else 1
        
        # 16. RandomString (check for random-looking domain)
        import math
        def calculate_entropy(string):
            if not string:
                return 0
            entropy = 0
            for x in set(string):
                p_x = string.count(x) / len(string)
                if p_x > 0:
                    entropy += - p_x * math.log2(p_x)
            return entropy
        
        domain_entropy = calculate_entropy(domain_info.domain)
        features["RandomString"] = 1 if domain_entropy > 3.5 else 0
        
        # 17. IpAddress
        ip_pattern = re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.netloc)
        features["IpAddress"] = 1 if ip_pattern else 0
        
        # 18. DomainInSubdomains (suspicious if main domain appears in subdomain)
        features["DomainInSubdomains"] = 1 if domain_info.subdomain and domain_info.domain in domain_info.subdomain else 0
        
        # 19. DomainInPaths
        features["DomainInPaths"] = 1 if domain_info.domain in path else 0
        
        # 20. HttpsInHostname (suspicious: https in domain name)
        features["HttpsInHostname"] = 1 if "https" in parsed.netloc.lower() else 0
        
        # 21. HostnameLength
        features["HostnameLength"] = len(parsed.netloc)
        
        # 22. PathLength
        features["PathLength"] = len(path)
        
        # 23. QueryLength
        features["QueryLength"] = len(query)
        
        # 24. DoubleSlashInPath
        features["DoubleSlashInPath"] = 1 if "//" in path else 0
        
        # 25. NumSensitiveWords
        sensitive_words = ['secure', 'account', 'update', 'banking', 'confirm', 
                          'login', 'signin', 'verify', 'password', 'payment']
        features["NumSensitiveWords"] = sum(1 for word in sensitive_words if word in url.lower())
        
        # 26. EmbeddedBrandName (check for brand names in suspicious contexts)
        brands = ['paypal', 'google', 'facebook', 'amazon', 'microsoft', 'apple']
        domain_lower = domain_info.domain.lower()
        features["EmbeddedBrandName"] = 1 if any(
            brand in domain_lower and domain_lower != brand 
            for brand in brands
        ) else 0
        
        # HTML-based features (27-48)
        # These require fetching the webpage - use defaults if get_html=False
        if get_html:
            try:
                response = requests.get(url, timeout=5, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Get all links
                links = soup.find_all('a', href=True)
                total_links = len(links)
                
                if total_links > 0:
                    # 27. PctExtHyperlinks
                    ext_links = sum(1 for link in links if not link['href'].startswith(parsed.netloc))
                    features["PctExtHyperlinks"] = ext_links / total_links
                    
                    # 28. PctExtResourceUrls
                    resources = soup.find_all(['img', 'script', 'link'])
                    total_resources = len(resources)
                    ext_resources = 0
                    for res in resources:
                        src = res.get('src') or res.get('href')
                        if src and not src.startswith(parsed.netloc):
                            ext_resources += 1
                    features["PctExtResourceUrls"] = ext_resources / total_resources if total_resources > 0 else 0
                    
                    # 29. ExtFavicon
                    favicon = soup.find('link', rel='icon')
                    features["ExtFavicon"] = 1 if favicon and parsed.netloc not in str(favicon.get('href', '')) else 0
                    
                    # 30. InsecureForms
                    forms = soup.find_all('form')
                    features["InsecureForms"] = 1 if any(form.get('action', '').startswith('http:') for form in forms) else 0
                    
                    # 31. RelativeFormAction
                    features["RelativeFormAction"] = 1 if any(not form.get('action', '').startswith('http') for form in forms) else 0
                    
                    # 32. ExtFormAction
                    features["ExtFormAction"] = 1 if any(parsed.netloc not in form.get('action', '') for form in forms) else 0
                    
                    # 33. AbnormalFormAction
                    features["AbnormalFormAction"] = 1 if any(form.get('action') in ['', '#', 'about:blank'] for form in forms) else 0
                    
                    # 34. PctNullSelfRedirectHyperlinks
                    null_links = sum(1 for link in links if link['href'] in ['#', '', 'javascript:void(0)'])
                    features["PctNullSelfRedirectHyperlinks"] = null_links / total_links
                    
                else:
                    # No links found - set defaults
                    features["PctExtHyperlinks"] = 0
                    features["PctExtResourceUrls"] = 0
                    features["ExtFavicon"] = 0
                    features["InsecureForms"] = 0
                    features["RelativeFormAction"] = 0
                    features["ExtFormAction"] = 0
                    features["AbnormalFormAction"] = 0
                    features["PctNullSelfRedirectHyperlinks"] = 0
                
                # 35-48: Additional HTML features
                features["FrequentDomainNameMismatch"] = 0  # Complex to detect
                features["FakeLinkInStatusBar"] = 0  # Requires JavaScript analysis
                features["RightClickDisabled"] = 1 if 'oncontextmenu' in response.text.lower() else 0
                features["PopUpWindow"] = 1 if 'window.open' in response.text.lower() else 0
                features["SubmitInfoToEmail"] = 1 if 'mailto:' in response.text.lower() else 0
                features["IframeOrFrame"] = 1 if soup.find('iframe') or soup.find('frame') else 0
                features["MissingTitle"] = 1 if not soup.find('title') or not soup.find('title').text.strip() else 0
                features["ImagesOnlyInForm"] = 0  # Complex to detect
                
                # Runtime features (RT suffix) - use -1 for "not applicable"
                features["SubdomainLevelRT"] = features["SubdomainLevel"]
                features["UrlLengthRT"] = 1 if features["UrlLength"] > 54 else -1
                features["PctExtResourceUrlsRT"] = 1 if features["PctExtResourceUrls"] > 0.22 else -1
                features["AbnormalExtFormActionR"] = features["AbnormalFormAction"]
                features["ExtMetaScriptLinkRT"] = -1  # Complex
                features["PctExtNullSelfRedirectHyperlinksRT"] = 1 if features["PctNullSelfRedirectHyperlinks"] > 0.5 else -1
                
            except:
                # If HTML fetch fails, use safe defaults
                features.update(get_default_html_features())
        else:
            # Use defaults when not fetching HTML (for real-time prediction)
            features.update(get_default_html_features())
            
    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return safe defaults on error
        return get_all_default_features()
    
    return features


def get_default_html_features():
    """Default values for HTML-based features when HTML is not fetched"""
    return {
        "PctExtHyperlinks": 0.0,
        "PctExtResourceUrls": 0.0,
        "ExtFavicon": 0,
        "InsecureForms": 0,
        "RelativeFormAction": 0,
        "ExtFormAction": 0,
        "AbnormalFormAction": 0,
        "PctNullSelfRedirectHyperlinks": 0.0,
        "FrequentDomainNameMismatch": 0,
        "FakeLinkInStatusBar": 0,
        "RightClickDisabled": 0,
        "PopUpWindow": 0,
        "SubmitInfoToEmail": 0,
        "IframeOrFrame": 0,
        "MissingTitle": 0,
        "ImagesOnlyInForm": 0,
        "SubdomainLevelRT": 1,
        "UrlLengthRT": 1,
        "PctExtResourceUrlsRT": 1,
        "AbnormalExtFormActionR": 1,
        "ExtMetaScriptLinkRT": -1,
        "PctExtNullSelfRedirectHyperlinksRT": 1
    }


def get_all_default_features():
    """Complete default feature set"""
    defaults = {
        "NumDots": 2,
        "SubdomainLevel": 1,
        "PathLevel": 2,
        "UrlLength": 30,
        "NumDash": 0,
        "NumDashInHostname": 0,
        "AtSymbol": 0,
        "TildeSymbol": 0,
        "NumUnderscore": 0,
        "NumPercent": 0,
        "NumQueryComponents": 0,
        "NumAmpersand": 0,
        "NumHash": 0,
        "NumNumericChars": 0,
        "NoHttps": 0,
        "RandomString": 0,
        "IpAddress": 0,
        "DomainInSubdomains": 0,
        "DomainInPaths": 0,
        "HttpsInHostname": 0,
        "HostnameLength": 15,
        "PathLength": 10,
        "QueryLength": 0,
        "DoubleSlashInPath": 0,
        "NumSensitiveWords": 0,
        "EmbeddedBrandName": 0
    }
    defaults.update(get_default_html_features())
    return defaults


# Quick test
if __name__ == "__main__":
    # Test without HTML fetching (faster)
    test_urls = [
        "https://www.google.com",
        "http://secure-paypal.tk/login.php"
    ]
    
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_features(url, get_html=False)
        print(f"Features extracted: {len(features)}")
        print(f"First 5 features: {dict(list(features.items())[:5])}")