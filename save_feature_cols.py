import pandas as pd
import json

# Step 1: Load your dataset
data = pd.read_csv("data.csv")

# Step 2: Check columns
print("Columns in data:", list(data.columns))

# Step 3: Remove the label column (jisko model ne predict kiya tha)
label_col = 'CLASS_LABEL'  # apne dataset ke label column ka naam daalo yahan
if label_col in data.columns:
    feature_cols = list(data.columns)
    feature_cols.remove(label_col)
else:
    feature_cols = list(data.columns)

# Step 4: Save feature columns list to a JSON file
with open("feature_cols.json", "w") as f:
    json.dump(feature_cols, f)

print("Feature columns saved to feature_cols.json")
