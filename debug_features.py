# debug_features.py -- overwrite with this exact content
import os, json, pickle
import pandas as pd
import numpy as np

print("DEBUG START")   # <-- make sure at least this prints

# make sure we import your feature extractor
try:
    import full_feature_extraction as fe
    print("Imported full_feature_extraction OK")
except Exception as e:
    print("Import error for full_feature_extraction:", e)
    fe = None

URL = "https://www.google.com/"

MODEL_PATH = "model.pkl"
FEATURE_COLS_PATH = "feature_cols.json"

print("Checking files...")
print("model.pkl exists:", os.path.exists(MODEL_PATH))
print("feature_cols.json exists:", os.path.exists(FEATURE_COLS_PATH))

if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURE_COLS_PATH):
    print("Missing required files. Exiting.")
    raise SystemExit

with open(FEATURE_COLS_PATH, "r") as f:
    FEATURE_COLS = json.load(f)
print("Loaded FEATURE_COLS count:", len(FEATURE_COLS))

# extract features
if fe is None:
    print("No extractor available. Exiting.")
    raise SystemExit

print("Calling extract_features() ...")
try:
    feat_out = fe.extract_features(URL)
    print("extract_features returned type:", type(feat_out))
except Exception as e:
    print("extract_features raised exception:", e)
    raise

# print small confirmation of returned content
if isinstance(feat_out, dict):
    print("Returned keys count:", len(feat_out))
    # show only non-zero keys for clarity
    non_zero = {k:v for k,v in feat_out.items() if (isinstance(v,(int,float)) and v!=0) or (not isinstance(v,(int,float)) and v)}
    print("Non-zero/True returned keys (count):", len(non_zero))
    for k,v in list(non_zero.items())[:100]:
        print(f"  {k}: {v}")
elif isinstance(feat_out, (list, tuple, np.ndarray, pd.Series, pd.DataFrame)):
    print("Returned as sequence/array/series/dataframe. length or shape:", getattr(feat_out, "shape", len(feat_out)))
else:
    print("Returned unexpected type:", type(feat_out))

# convert to DataFrame aligned to FEATURE_COLS
def make_df(feat_out):
    if isinstance(feat_out, dict):
        df = pd.DataFrame([feat_out])
    elif isinstance(feat_out, pd.DataFrame):
        df = feat_out.reset_index(drop=True)
    elif isinstance(feat_out, pd.Series):
        df = feat_out.to_frame().T.reset_index(drop=True)
    else:
        arr = np.array(feat_out).reshape(1, -1)
        if arr.shape[1] == len(FEATURE_COLS):
            df = pd.DataFrame(arr, columns=FEATURE_COLS)
        else:
            df = pd.DataFrame(arr)
    # align
    for c in FEATURE_COLS:
        if c not in df.columns:
            df[c] = 0
    df = df[FEATURE_COLS]
    return df

X = make_df(feat_out)
print("Final DataFrame shape:", X.shape)
print("Non-zero columns in final DF:")
nz = X.loc[:, (X != 0).any(axis=0)]
if nz.shape[1] == 0:
    print("  (all zeros)")
else:
    for col in nz.columns:
        print(" ", col, "=", int(nz.iloc[0][col]))

# load model and predict
print("Loading model...")
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

print("Model loaded. Predicting...")
try:
    pred = model.predict(X)
    proba = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]
    print("Prediction:", int(pred[0]), "(1=phishing, 0=legit)")
    if proba is not None:
        print("Probabilities:", proba)
        print("Confidence for predicted class:", proba[int(pred[0])]*100, "%")
except Exception as e:
    print("Model prediction error:", e)
    print("Columns passed to model:", list(X.columns))
    raise

print("DEBUG END")
