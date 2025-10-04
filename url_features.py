# url_features.py

from urllib.parse import urlparse
import re

SENSITIVE = {"login", "secure", "account", "update", "bank", "verify", "signin", "confirm"}

def clean_url(u):
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u

def url_basic_features(url):
    u = clean_url(url)
    p = urlparse(u)
    hostname = p.hostname or ""
    path = p.path or ""
    query = p.query or ""
    full = u

    out = {}
    out["NumDots"] = full.count(".")
    out["NumDash"] = full.count("-")
    out["NumDashInHostname"] = hostname.count("-")
    out["NumUnderscore"] = full.count("_")
    out["NumPercent"] = full.count("%")
    out["NumAmpersand"] = full.count("&")
    out["NumHash"] = full.count("#")
    out["NumQueryComponents"] = len(query.split("&")) if query else 0
    out["NumNumericChars"] = sum(c.isdigit() for c in full)
    out["UrlLength"] = len(full)
    out["PathLength"] = len(path)
    out["QueryLength"] = len(query)
    out["PathLevel"] = path.count("/") if path else 0
    out["SubdomainLevel"] = max(0, hostname.count(".") - 1)
    out["HostnameLength"] = len(hostname)
    out["IpAddress"] = 1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname) else 0
    out["NoHttps"] = 1 if p.scheme != "https" else 0
    out["AtSymbol"] = 1 if "@" in full else 0
    out["NumSensitiveWords"] = sum(1 for w in SENSITIVE if w in full.lower())
    return out
