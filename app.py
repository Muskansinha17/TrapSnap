from flask import Flask, render_template, request, jsonify
import pickle
import pandas as pd
from feature_extraction import extract_features
import tldextract
import re

app = Flask(__name__)

# Whitelist of trusted domains
WHITELIST = {
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'amazon.com', 'amazon.in', 'flipkart.com', 'myntra.com',
    'microsoft.com', 'apple.com', 'twitter.com', 'linkedin.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org',
    'reddit.com', 'netflix.com', 'zoom.us', 'gmail.com',
    'yahoo.com', 'bing.com', 'whatsapp.com', 'telegram.org',
    'gov.in', 'nic.in', 'irctc.co.in', 'sbi.co.in',
    'icicibank.com', 'hdfcbank.com', 'axisbank.com'
}

MODEL = None
FEATURE_NAMES = None

def load_model():
    global MODEL, FEATURE_NAMES
    try:
        with open('phishing_model.pkl', 'rb') as f:
            model_data = pickle.load(f)
            MODEL = model_data['model']
            FEATURE_NAMES = model_data['feature_names']
        print("✅ Model loaded successfully!")
        return True
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return False

def is_whitelisted(url):
    try:
        domain_info = tldextract.extract(url)
        root_domain = f"{domain_info.domain}.{domain_info.suffix}".lower()
        return root_domain in WHITELIST
    except:
        return False

def check_character_substitution(domain):
    """Detect lookalike domains (g00gle, fac3book, etc.)"""
    known_brands = ['google', 'facebook', 'amazon', 'paypal', 'microsoft', 
                    'apple', 'netflix', 'instagram', 'twitter', 'linkedin']
    
    # Replace common substitutions
    normalized = domain.lower()
    normalized = normalized.replace('0', 'o').replace('1', 'l').replace('3', 'e')
    normalized = normalized.replace('$', 's').replace('@', 'a').replace('!', 'i')
    
    # Check if normalized version matches known brand
    for brand in known_brands:
        if normalized == brand or brand in normalized:
            # But original domain is different (has substitutions)
            if domain.lower() != brand:
                return True, brand
    
    return False, None

def check_suspicious_patterns(url):
    """Additional security checks for obvious phishing"""
    try:
        domain_info = tldextract.extract(url)
        domain = domain_info.domain.lower()
        
        # Check 1: Character substitution in domain
        has_substitution, brand = check_character_substitution(domain)
        if has_substitution:
            return True, f"Domain mimics '{brand}' using character substitution"
        
        # Check 2: IP address in URL
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_info.netloc):
            return True, "Using IP address instead of domain name"
        
        # Check 3: Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
        if any(url.lower().endswith(tld) for tld in suspicious_tlds):
            return True, f"Using suspicious TLD ({domain_info.suffix})"
        
        # Check 4: Too many subdomains
        if domain_info.subdomain and len(domain_info.subdomain.split('.')) > 3:
            return True, "Excessive subdomains detected"
        
        # Check 5: Domain contains brand name but isn't the brand
        brands = ['google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple']
        for brand in brands:
            if brand in domain and domain != brand:
                # Exception: google.com vs google.co.in
                if not domain.startswith(brand):
                    return True, f"Domain contains '{brand}' but is not official"
        
        # Check 6: Multiple dashes in domain (common in phishing)
        if domain.count('-') > 2:
            return True, "Excessive dashes in domain name"
        
        return False, None
        
    except:
        return False, None

def predict_url(url):
    result = {
        'url': url,
        'is_phishing': False,
        'confidence': 0,
        'label': 'LEGITIMATE',
        'message': '',
        'details': {}
    }
    
    if not url or len(url) < 4:
        result['message'] = 'Please enter a valid URL'
        return result
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        result['url'] = url
    
    # Check whitelist first
    if is_whitelisted(url):
        result['is_phishing'] = False
        result['confidence'] = 0
        result['label'] = 'SAFE'
        result['message'] = 'This is a trusted website from our whitelist'
        result['details']['whitelisted'] = True
        return result
    
    # Additional security checks before ML
    is_suspicious, reason = check_suspicious_patterns(url)
    if is_suspicious:
        result['is_phishing'] = True
        result['confidence'] = 95
        result['label'] = 'PHISHING'
        result['message'] = f'⚠️ Warning! {reason}'
        result['details'] = {
            'phishing_probability': 95,
            'legitimate_probability': 5,
            'whitelisted': False,
            'detection_method': 'Pattern-based detection'
        }
        return result
    
    if MODEL is None:
        result['message'] = 'Model not loaded. Please train the model first.'
        return result
    
    try:
        features = extract_features(url, get_html=False)
        feature_df = pd.DataFrame([features])[FEATURE_NAMES]
        
        prediction = MODEL.predict(feature_df)[0]
        probabilities = MODEL.predict_proba(feature_df)[0]
        
        phishing_prob = probabilities[1]
        legitimate_prob = probabilities[0]
        
        # Lower threshold to 70% for better detection
        if phishing_prob >= 0.70:
            result['is_phishing'] = True
            result['confidence'] = int(phishing_prob * 100)
            result['label'] = 'PHISHING'
            result['message'] = '⚠️ Warning! This website appears to be a phishing attempt.'
        elif phishing_prob >= 0.50:
            result['is_phishing'] = True
            result['confidence'] = int(phishing_prob * 100)
            result['label'] = 'SUSPICIOUS'
            result['message'] = '⚠️ This website looks suspicious. Proceed with caution.'
        else:
            result['is_phishing'] = False
            result['confidence'] = int(legitimate_prob * 100)
            result['label'] = 'SAFE'
            result['message'] = '✓ This website appears to be legitimate.'
        
        result['details'] = {
            'phishing_probability': int(phishing_prob * 100),
            'legitimate_probability': int(legitimate_prob * 100),
            'whitelisted': False,
            'features_analyzed': len(features),
            'detection_method': 'Machine Learning'
        }
        
        result['details']['key_features'] = {
            'has_https': features.get('NoHttps', 1) == 0,
            'uses_ip_address': features.get('IpAddress', 0) == 1,
            'suspicious_length': features.get('UrlLength', 0) > 75,
            'has_sensitive_words': features.get('NumSensitiveWords', 0) > 0
        }
        
    except Exception as e:
        result['message'] = f'Error analyzing URL: {str(e)}'
    
    return result

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        result = predict_url(url)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/batch-check', methods=['POST'])
def batch_check():
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'URLs array is required'}), 400
        
        results = []
        for url in urls:
            if url.strip():
                result = predict_url(url.strip())
                results.append(result)
        
        return jsonify({'results': results})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stats')
def stats():
    return jsonify({
        'model_loaded': MODEL is not None,
        'features_count': len(FEATURE_NAMES) if FEATURE_NAMES else 0,
        'whitelist_size': len(WHITELIST),
        'status': 'operational' if MODEL else 'model not loaded'
    })

if __name__ == '__main__':
    print("="*70)
    print("PHISHING DETECTION SYSTEM")
    print("="*70)
    print("\nStarting server...")

    if load_model():
        print(f"Features loaded: {len(FEATURE_NAMES)}")
        print(f"Whitelist domains: {len(WHITELIST)}")
        print("\n✅ System ready!")
        # Read port from environment (Railway / Heroku style)
        import os
        port = int(os.environ.get("PORT", 5000))
        host = "0.0.0.0"
        print(f"\n📱 Open in browser (locally): http://localhost:{port}")
        print("="*70)
        # NOTE: turn off debug in production
        app.run(debug=False, host=host, port=port)
    else:
        print("\n❌ Failed to load model!")
        print("Please train the model first using: python train_model.py")
        print("="*70)
