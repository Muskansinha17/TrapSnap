import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle

print("="*70)
print("PHISHING DETECTION - MODEL TRAINING")
print("="*70)

# Step 1: Load Dataset
print("\n[1/6] Loading dataset...")
try:
    df = pd.read_csv('data.csv')
    print(f"✅ Dataset loaded: {len(df)} samples")
except FileNotFoundError:
    print("❌ Error: data.csv not found!")
    print("\nPlease make sure you have 'data.csv' file in the project folder")
    exit()

# Step 2: Check dataset
print("\n[2/6] Checking dataset...")
print(f"Total columns: {len(df.columns)}")
print(f"Columns: {list(df.columns[:10])}...")

if 'CLASS_LABEL' not in df.columns:
    print("❌ Error: 'CLASS_LABEL' column not found in dataset!")
    exit()

print(f"\nClass Distribution:")
print(df['CLASS_LABEL'].value_counts())
phishing_count = sum(df['CLASS_LABEL'] == 1)
legitimate_count = sum(df['CLASS_LABEL'] == 0)
print(f"Phishing (1): {phishing_count} ({phishing_count/len(df)*100:.1f}%)")
print(f"Legitimate (0): {legitimate_count} ({legitimate_count/len(df)*100:.1f}%)")

# Step 3: Prepare data
print("\n[3/6] Preparing data...")

# Remove ID column if exists - IMPORTANT FIX
if 'id' in df.columns:
    df = df.drop('id', axis=1)
    print("✅ Removed 'id' column")
elif 'd' in df.columns:
    df = df.drop('d', axis=1)
    print("✅ Removed 'd' column")
else:
    print("ℹ️  No ID column found")

X = df.drop('CLASS_LABEL', axis=1)
y = df['CLASS_LABEL']

print(f"Features: {len(X.columns)}")
print(f"Samples: {len(X)}")

# Step 4: Balance dataset
print("\n[4/6] Balancing dataset...")
if abs(phishing_count - legitimate_count) > 1000:
    print("Dataset is imbalanced. Balancing...")
    
    phishing_df = df[df['CLASS_LABEL'] == 1]
    legitimate_df = df[df['CLASS_LABEL'] == 0]
    
    min_size = min(len(phishing_df), len(legitimate_df))
    phishing_df = phishing_df.sample(n=min_size, random_state=42)
    legitimate_df = legitimate_df.sample(n=min_size, random_state=42)
    
    df_balanced = pd.concat([phishing_df, legitimate_df]).sample(frac=1, random_state=42)
    
    X = df_balanced.drop('CLASS_LABEL', axis=1)
    y = df_balanced['CLASS_LABEL']
    
    print(f"✅ Dataset balanced: {len(X)} total samples")
    print(f"   Phishing: {sum(y==1)}")
    print(f"   Legitimate: {sum(y==0)}")
else:
    print("✅ Dataset is already balanced")

# Step 5: Train Model
print("\n[5/6] Training Random Forest model...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Training samples: {len(X_train)}")
print(f"Testing samples: {len(X_test)}")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
    verbose=0
)

print("\nTraining in progress...")
model.fit(X_train, y_train)
print("✅ Training complete!")

# Step 6: Evaluate
print("\n[6/6] Evaluating model...")

train_pred = model.predict(X_train)
train_acc = accuracy_score(y_train, train_pred)
print(f"\n📊 Training Accuracy: {train_acc*100:.2f}%")

y_pred = model.predict(X_test)
test_acc = accuracy_score(y_test, y_pred)
print(f"📊 Testing Accuracy: {test_acc*100:.2f}%")

print("\n" + "="*70)
print("CONFUSION MATRIX")
print("="*70)
cm = confusion_matrix(y_test, y_pred)
print(f"\n                Predicted Legitimate  |  Predicted Phishing")
print(f"Actual Legitimate      {cm[0][0]:6d}          |      {cm[0][1]:6d}")
print(f"Actual Phishing        {cm[1][0]:6d}          |      {cm[1][1]:6d}")

print(f"\n✓ Correctly identified legitimate: {cm[0][0]}")
print(f"✗ False positive (legit as phishing): {cm[0][1]}")
print(f"✗ False negative (phishing as legit): {cm[1][0]}")
print(f"✓ Correctly identified phishing: {cm[1][1]}")

print("\n" + "="*70)
print("CLASSIFICATION REPORT")
print("="*70)
print(classification_report(y_test, y_pred, 
                          target_names=['Legitimate', 'Phishing']))

print("\n" + "="*70)
print("TOP 10 MOST IMPORTANT FEATURES")
print("="*70)
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

for idx, row in feature_importance.head(10).iterrows():
    print(f"{row['feature']:30s} : {row['importance']:.4f}")

# IMPORTANT: Check if 'id' is in top features (it shouldn't be)
if 'id' in feature_importance.head(10)['feature'].values:
    print("\n⚠️  WARNING: 'id' column found in top features!")
    print("This means the model learned from IDs, not actual patterns.")
    print("Model may not work on new URLs!")

# Save Model
print("\n" + "="*70)
print("SAVING MODEL")
print("="*70)

model_data = {
    'model': model,
    'feature_names': list(X.columns)
}

with open('phishing_model.pkl', 'wb') as f:
    pickle.dump(model_data, f)

print("✅ Model saved to 'phishing_model.pkl'")
print(f"   Features saved: {len(X.columns)}")

print("\n" + "="*70)
print("✅ TRAINING COMPLETED SUCCESSFULLY!")
print("="*70)
print(f"\n📊 Model Performance:")
print(f"   Training Accuracy: {train_acc*100:.2f}%")
print(f"   Testing Accuracy: {test_acc*100:.2f}%")
print(f"   Total Features: {len(X.columns)}")

print(f"\n🚀 Next Steps:")
print(f"   1. Run the Flask app: python app.py")
print(f"   2. Open browser: http://localhost:5000")
print(f"   3. Start detecting phishing URLs!")

print("\n" + "="*70)