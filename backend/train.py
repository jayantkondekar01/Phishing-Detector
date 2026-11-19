"""
Training Script — Train the LSVC phishing classifier on a URL dataset.

Usage:
    python train.py --dataset path/to/urls.csv

Expected CSV format:
    url,label
    https://google.com,legitimate
    http://phish-login.tk/verify,phishing

The script:
    1. Loads the dataset
    2. Extracts URL features for every row
    3. Scales features with StandardScaler
    4. Trains a LinearSVC model (best performer from evaluation — 91%)
    5. Evaluates on a test split
    6. Saves model + scaler to backend/trained_models/
"""

import argparse
import sys
import time
import logging

import numpy as np
import pandas as pd
import joblib
from sklearn.svm import LinearSVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

from config import ML_MODEL_PATH, SCALER_PATH
from models.url_features import extract_features, get_feature_names, features_to_vector

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(message)s")
logger = logging.getLogger("trainer")


def load_dataset(path: str) -> pd.DataFrame:
    """Load a CSV dataset with 'url' and 'label' columns."""
    logger.info("Loading dataset from %s ...", path)
    df = pd.read_csv(path)

    # Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]

    if "url" not in df.columns:
        raise ValueError("Dataset must have a 'url' column")
    if "label" not in df.columns:
        # Try common alternatives
        for alt in ["type", "class", "status", "phishing", "is_phishing"]:
            if alt in df.columns:
                df.rename(columns={alt: "label"}, inplace=True)
                break
        else:
            raise ValueError("Dataset must have a 'label' column")

    # Normalize labels to 0/1
    label_map = {
        "legitimate": 0, "benign": 0, "safe": 0, "good": 0, "0": 0, 0: 0,
        "phishing": 1, "malicious": 1, "bad": 1, "phish": 1, "1": 1, 1: 1,
    }
    df["label"] = df["label"].astype(str).str.strip().str.lower().map(label_map)
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    logger.info(
        "Dataset loaded: %d rows | Legitimate: %d | Phishing: %d",
        len(df), (df["label"] == 0).sum(), (df["label"] == 1).sum(),
    )
    return df


def extract_all_features(df: pd.DataFrame) -> np.ndarray:
    """Extract features for every URL in the dataframe."""
    logger.info("Extracting features from %d URLs...", len(df))
    feature_names = get_feature_names()
    all_features = []
    errors = 0

    for i, url in enumerate(df["url"]):
        try:
            feats = extract_features(str(url))
            all_features.append([float(feats[f]) for f in feature_names])
        except Exception:
            # Use zeros for broken URLs
            all_features.append([0.0] * len(feature_names))
            errors += 1

        if (i + 1) % 10000 == 0:
            logger.info("  Processed %d / %d URLs...", i + 1, len(df))

    if errors:
        logger.warning("  %d URLs failed feature extraction (zeroed out)", errors)

    return np.array(all_features)


def train(dataset_path: str, test_size: float = 0.1):
    """Full training pipeline."""
    start = time.time()

    # 1. Load data
    df = load_dataset(dataset_path)
    X = extract_all_features(df)
    y = df["label"].values

    # 2. Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y,
    )
    logger.info("Train: %d | Test: %d", len(X_train), len(X_test))

    # 3. Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 4. Train LinearSVC
    logger.info("Training LinearSVC model...")
    model = LinearSVC(
        C=1.0,
        loss="squared_hinge",
        max_iter=5000,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train_scaled, y_train)

    # 5. Evaluate
    y_pred = model.predict(X_test_scaled)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    logger.info("=" * 50)
    logger.info("EVALUATION RESULTS")
    logger.info("=" * 50)
    logger.info("Accuracy:  %.4f", accuracy)
    logger.info("Precision: %.4f", precision)
    logger.info("Recall:    %.4f", recall)
    logger.info("F1 Score:  %.4f", f1)
    logger.info("-" * 50)
    logger.info("\n%s", classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    logger.info("Confusion Matrix:\n%s", confusion_matrix(y_test, y_pred))

    # 6. Save
    joblib.dump(model, ML_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    logger.info("Model saved to: %s", ML_MODEL_PATH)
    logger.info("Scaler saved to: %s", SCALER_PATH)

    elapsed = time.time() - start
    logger.info("Training completed in %.1f seconds", elapsed)

    return accuracy, precision, recall, f1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the phishing detection model")
    parser.add_argument(
        "--dataset", "-d", required=True,
        help="Path to CSV file with 'url' and 'label' columns",
    )
    parser.add_argument(
        "--test-size", "-t", type=float, default=0.1,
        help="Fraction of data to use for testing (default: 0.1)",
    )
    args = parser.parse_args()
    train(args.dataset, args.test_size)
