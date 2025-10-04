# full_feature_extraction.py
from url_features import url_basic_features, clean_url
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re

HEADERS = {"User-Agent": "Mozilla/5.0"}

def fetch_page(url, timeout=6):
    try:
        if not url.startswith(("http://","https://")):
            url = "http://" + url
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        return r.status_code, r.text
    except Exception:
        return None, None

def pct_external_links(html, base_url):
    soup = BeautifulSoup(html, "lxml")
    anchors = soup.find_all("a", href=True)
    if not anchors:
        return 0.0, 0.0
    base_host = urlparse(base_url).hostname or ""
    ext = 0
    nullself = 0
    for a in anchors:
        href = a.get("href", "").strip()
        if href in ("", "#", "javascript:void(0)"):
            nullself += 1
            continue
        href_full = urljoin(base_url, href)
        host = urlparse(href_full).hostname or ""
        if host and host != base_host:
            ext += 1
    total = len(anchors)
    return ext / total, nullself / total

def pct_external_resources(html, base_url):
    soup = BeautifulSoup(html, "lxml")
    resources = []
    # gather src/href of common resource tags
    for tag in soup.find_all(["img","script","iframe"]):
        src = tag.get("src")
        if src:
            resources.append(src)
    for tag in soup.find_all("link", href=True):
        resources.append(tag.get("href"))
    if not resources:
        return 0.0
    base_host = urlparse(base_url).hostname or ""
    ext = 0
    for r in resources:
        rfull = urljoin(base_url, r)
        host = urlparse(rfull).hostname or ""
        if host and host != base_host:
            ext += 1
    return ext / len(resources)

def has_ext_favicon(html, base_url):
    soup = BeautifulSoup(html, "lxml")
    favs = soup.find_all("link", rel=re.compile("icon", re.I))
    base_host = urlparse(base_url).hostname or ""
    for f in favs:
        href = f.get("href")
        if href:
            href_full = urljoin(base_url, href)
            host = urlparse(href_full).hostname or ""
            if host and host != base_host:
                return 1
    return 0

def form_features(html, base_url):
    soup = BeautifulSoup(html, "lxml")
    forms = soup.find_all("form")
    insecure = 0
    ext_form_action = 0
    relative_action = 0
    submit_email = 0
    abnormal = 0
    base_host = urlparse(base_url).hostname or ""
    for form in forms:
        action = form.get("action") or ""
        action_full = urljoin(base_url, action) if action else ""
        host = urlparse(action_full).hostname or ""
        if action == "" or action.startswith("javascript:"):
            relative_action += 1
        if host and host != base_host:
            ext_form_action += 1
        if base_url.startswith("https") and action_full.startswith("http://"):
            insecure += 1
        if "mailto:" in (action_full or ""):
            submit_email += 1
    return {
        "InsecureForms": insecure,
        "RelativeFormAction": relative_action,
        "ExtFormAction": ext_form_action,
        "SubmitInfoToEmail": submit_email,
        "AbnormalFormAction": abnormal
    }

def count_iframes(html):
    soup = BeautifulSoup(html, "lxml")
    iframes = soup.find_all("iframe")
    frames = soup.find_all("frame")
    return len(iframes) + len(frames)

def extract_features(url):
    """
    Returns a dict of features with keys matching your feature_cols.json.
    """
    # start with url-based
    features = url_basic_features(url)

    # ensure some keys exist even if missing in url_basic_features
    keys_defaults = [
        "PctExtHyperlinks","PctNullSelfRedirectHyperlinks","PctExtResourceUrls",
        "ExtFavicon","InsecureForms","RelativeFormAction","ExtFormAction",
        "AbnormalFormAction","PctNullSelfRedirectHyperlinks","SubmitInfoToEmail",
        "IframeOrFrame"
    ]
    for k in keys_defaults:
        if k not in features:
            features[k] = 0

    # fetch page and compute content features
    status, html = fetch_page(url)
    if html:
        try:
            pct_ext_links, pct_null = pct_external_links(html, url)
            features["PctExtHyperlinks"] = pct_ext_links
            features["PctNullSelfRedirectHyperlinks"] = pct_null
        except Exception:
            features["PctExtHyperlinks"] = 0
            features["PctNullSelfRedirectHyperlinks"] = 0

        try:
            features["PctExtResourceUrls"] = pct_external_resources(html, url)
        except Exception:
            features["PctExtResourceUrls"] = 0

        try:
            features["ExtFavicon"] = has_ext_favicon(html, url)
        except Exception:
            features["ExtFavicon"] = 0

        try:
            ff = form_features(html, url)
            features.update(ff)
        except Exception:
            features["InsecureForms"] = 0
            features["RelativeFormAction"] = 0
            features["ExtFormAction"] = 0
            features["SubmitInfoToEmail"] = 0
            features["AbnormalFormAction"] = 0

        try:
            features["IframeOrFrame"] = 1 if count_iframes(html) > 0 else 0
        except Exception:
            features["IframeOrFrame"] = 0
    else:
        # fetch failed; leave defaults (zeros)
        pass

    # ensure all feature names are present (some models expect exact keys)
    return features
