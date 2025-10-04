import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

print("CWD:", os.getcwd())
print("Files:", os.listdir())

# ---------- LOAD ----------
csv_path = "data.csv"   # your file
data = pd.read_csv("data.csv")  # CSV file load karo
print("Columns in dataset:", list(data.columns))  # Columns print karo

print("Loaded shape:", data.shape)
print("Columns:", list(data.columns))

# ---------- LABEL COLUMN ----------
label_col = "label"
if label_col not in data.columns:
    # fallback: use last column as label
    label_col = data.columns[-1]
    print(f"'label' not found — using last column as label: '{label_col}'")

# ---------- SIMPLE PREPROCESSING ----------
# drop rows where label is missing
data = data.dropna(subset=[label_col])

# features X and target y
X = data.drop(columns=[label_col])
y = data[label_col]

# If any non-numeric columns exist, convert using get_dummies
non_numeric = X.select_dtypes(exclude=["number"]).columns.tolist()
if non_numeric:
    print("Non-numeric columns found, applying one-hot:", non_numeric)
    X = pd.get_dummies(X, columns=non_numeric, drop_first=True)

# Fill remaining missing numeric values with 0 (or you can use median)
if X.isnull().any().any():
    print("Filling remaining missing values with 0")
    X = X.fillna(0)

print("Final X shape:", X.shape)
print("y distribution:\n", y.value_counts())

# ---------- SPLIT + TRAIN ----------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y if len(y.unique())>1 else None
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

acc = model.score(X_test, y_test)
print("Accuracy:", acc)

# ---------- SAVE ----------
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)
print("Saved model.pkl")
