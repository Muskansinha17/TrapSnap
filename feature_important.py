# feature_importance.py
import json, pickle, os
import pandas as pd

MODEL = "model.pkl"
FEAT = "feature_cols.json"

if not os.path.exists(MODEL) or not os.path.exists(FEAT):
    raise SystemExit("model.pkl or feature_cols.json missing")

with open(FEAT) as f:
    cols = json.load(f)

with open(MODEL,"rb") as f:
    model = pickle.load(f)

if hasattr(model, "feature_importances_"):
    fi = model.feature_importances_
    df = pd.DataFrame({"feature": cols, "importance": fi})
    df = df.sort_values("importance", ascending=False).reset_index(drop=True)
    print(df.head(30).to_string(index=False))
else:
    print("Model has no feature_importances_.")
