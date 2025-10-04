# test_url_features.py
from url_features import url_basic_features

urls = [
    "https://www.google.com",
    "http://example.com/path?x=1&y=2",
    "http://123.45.67.89/login"
]

for u in urls:
    feats = url_basic_features(u)
    print("URL:", u)
    for k, v in feats.items():
        print(f"  {k:25s}: {v}")
    print("-" * 40)
