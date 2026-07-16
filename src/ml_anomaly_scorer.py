#!/usr/bin/env python3
"""
ML Ensemble Anomaly Scorer for LOLBins Detection Engine
========================================================
Trains an ensemble of three unsupervised anomaly detection models on benign
baseline data and scores new events on a 0-100 "unusualness" scale.

Ensemble Architecture:
- Isolation Forest (weight: 0.4) — Fast, tree-based anomaly isolation
- Local Outlier Factor (weight: 0.3) — Density-based local anomaly detection
- One-Class SVM (weight: 0.3) — Kernel-based boundary learning

Design Decision: We use three complementary algorithms because each catches
different types of anomalies. IF excels at isolating globally unusual points,
LOF catches locally unusual points in dense clusters, and OCSVM defines a
smooth boundary around normal data. The ensemble is more robust than any
single model.

Author: Eswar Achari
"""

import os
import sys
import warnings
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

# Suppress sklearn convergence warnings for cleaner output
warnings.filterwarnings('ignore', category=UserWarning)


class MLAnomalyScorer:
    """
    Ensemble ML anomaly scorer that trains on benign-only data and scores
    events on a 0-100 scale where 100 = most anomalous.
    
    Training follows unsupervised anomaly detection best practice:
    the model only sees "normal" data during training and learns to
    flag deviations from that learned normal distribution.
    """

    # Features used for ML scoring — must match feature_engineering.py output
    FEATURE_COLUMNS = [
        'is_known_lolbin', 'is_scripting_engine',
        'command_line_length', 'command_line_entropy',
        'has_suspicious_flag', 'contains_url', 'contains_ip_address',
        'has_base64_pattern', 'argument_count', 'suspicious_argument_ratio',
        'has_encoded_command', 'has_download_indicator',
        'process_ancestry_depth', 'parent_is_office_app',
        'parent_is_browser', 'parent_is_script_engine',
        'hour_of_day', 'is_off_hours', 'is_weekend',
        'parent_child_pair_rarity', 'command_length_zscore',
        'entropy_zscore', 'is_system_user', 'integrity_encoded',
    ]

    # Ensemble weights (sum to 1.0)
    WEIGHTS = {
        'isolation_forest': 0.4,
        'lof': 0.3,
        'ocsvm': 0.3,
    }

    # Human-readable descriptions for feature explanations
    FEATURE_DESCRIPTIONS = {
        'command_line_entropy': 'high command line entropy (possible obfuscation)',
        'command_line_length': 'unusually long command line',
        'is_known_lolbin': 'process is a known LOLBin',
        'has_suspicious_flag': 'suspicious command line flags detected',
        'contains_url': 'URL found in command line',
        'contains_ip_address': 'IP address in command line',
        'has_base64_pattern': 'base64-encoded content detected',
        'has_encoded_command': 'encoded PowerShell command',
        'has_download_indicator': 'download activity indicator',
        'is_off_hours': 'execution during off-hours (midnight-5am)',
        'is_weekend': 'weekend execution',
        'parent_child_pair_rarity': 'unusual parent-child process relationship',
        'command_length_zscore': 'command length significantly above baseline',
        'entropy_zscore': 'entropy significantly above baseline',
        'parent_is_office_app': 'spawned by Office application',
        'parent_is_script_engine': 'spawned by script engine',
        'suspicious_argument_ratio': 'high ratio of suspicious arguments',
        'process_ancestry_depth': 'deep process chain (possible multi-stage)',
        'argument_count': 'unusual number of arguments',
        'is_scripting_engine': 'scripting engine execution',
    }

    def __init__(self):
        """Initialize scorer with empty models."""
        self.models = {}
        self.scaler = StandardScaler()
        self.baseline_stats = {}  # Per-feature mean/std from training data
        self.is_trained = False
        self._score_ranges = {}  # Min/max raw scores for normalization

    def train(self, features_df: pd.DataFrame):
        """
        Train the ensemble on benign-only feature data.
        
        Args:
            features_df: DataFrame with feature columns from FeatureEngineer.
                         Should contain ONLY benign events.
        """
        print("  [*] Training ML ensemble on benign baseline...")

        # Select and prepare features
        X = self._prepare_features(features_df)
        print(f"    Training data shape: {X.shape}")

        # Fit scaler on benign data
        X_scaled = self.scaler.fit_transform(X)

        # Store baseline statistics for explainability
        for i, col in enumerate(self.FEATURE_COLUMNS):
            if col in features_df.columns:
                vals = features_df[col].values
            else:
                vals = X[:, i]
            self.baseline_stats[col] = {
                'mean': float(np.nanmean(vals)),
                'std': float(max(np.nanstd(vals), 0.001)),  # Avoid div by zero
                'min': float(np.nanmin(vals)),
                'max': float(np.nanmax(vals)),
            }

        # Train Model 1: Isolation Forest
        print("    Training Isolation Forest...")
        self.models['isolation_forest'] = IsolationForest(
            contamination=0.05,
            n_estimators=200,
            random_state=42,
            n_jobs=-1,
        )
        self.models['isolation_forest'].fit(X_scaled)

        # Train Model 2: Local Outlier Factor (novelty mode for prediction)
        print("    Training Local Outlier Factor...")
        self.models['lof'] = LocalOutlierFactor(
            n_neighbors=20,
            novelty=True,
            contamination=0.05,
        )
        self.models['lof'].fit(X_scaled)

        # Train Model 3: One-Class SVM
        print("    Training One-Class SVM...")
        self.models['ocsvm'] = OneClassSVM(
            kernel='rbf',
            gamma='auto',
            nu=0.05,
        )
        self.models['ocsvm'].fit(X_scaled)

        # Compute score ranges on training data for normalization
        self._compute_score_ranges(X_scaled)

        self.is_trained = True
        print("    ✓ All 3 models trained successfully")

    def _prepare_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract and clean feature columns for ML input."""
        available_cols = [c for c in self.FEATURE_COLUMNS if c in df.columns]

        if not available_cols:
            raise ValueError(
                f"No feature columns found. Expected: {self.FEATURE_COLUMNS[:5]}...")

        X = df[available_cols].copy()

        # Fill missing values with 0 (safe default for binary/count features)
        X = X.fillna(0)

        # Replace infinities with large finite values
        X = X.replace([np.inf, -np.inf], 0)

        return X.values.astype(np.float64)

    def _compute_score_ranges(self, X_scaled: np.ndarray):
        """Compute raw score ranges for normalization."""
        # Get raw scores from each model on training data
        for name, model in self.models.items():
            if name == 'ocsvm':
                raw = -model.decision_function(X_scaled)
            else:
                raw = -model.score_samples(X_scaled)
            self._score_ranges[name] = {
                'min': float(np.min(raw)),
                'max': float(np.max(raw)),
            }

    def score(self, features_df: pd.DataFrame) -> np.ndarray:
        """
        Score events on a 0-100 anomaly scale.
        
        Args:
            features_df: DataFrame with feature columns.
            
        Returns:
            Array of anomaly scores (0-100), one per event.
            Higher = more anomalous.
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")

        X = self._prepare_features(features_df)
        X_scaled = self.scaler.transform(X)

        # Get normalized scores from each model
        model_scores = {}

        for name, model in self.models.items():
            if name == 'ocsvm':
                raw = -model.decision_function(X_scaled)
            else:
                raw = -model.score_samples(X_scaled)

            # Normalize to 0-100 using training data range
            sr = self._score_ranges[name]
            score_range = max(sr['max'] - sr['min'], 0.001)
            normalized = (raw - sr['min']) / score_range * 100
            normalized = np.clip(normalized, 0, 100)
            model_scores[name] = normalized

        # Weighted ensemble
        ensemble_score = (
            self.WEIGHTS['isolation_forest'] * model_scores['isolation_forest'] +
            self.WEIGHTS['lof'] * model_scores['lof'] +
            self.WEIGHTS['ocsvm'] * model_scores['ocsvm']
        )

        return np.clip(ensemble_score, 0, 100)

    def explain(self, event_features: pd.Series,
                score: float = None) -> str:
        """
        Generate a human-readable explanation of why an event scored high.
        
        Compares each feature value against the benign baseline mean/std
        and reports features that deviate by more than 2 standard deviations.
        
        Args:
            event_features: Series with feature values for a single event.
            score: Optional pre-computed anomaly score.
            
        Returns:
            Human-readable explanation string.
        """
        if not self.baseline_stats:
            return "No baseline statistics available for explanation."

        deviations = []

        for col in self.FEATURE_COLUMNS:
            if col not in self.baseline_stats or col not in event_features.index:
                continue

            value = event_features.get(col, 0)
            if pd.isna(value):
                continue

            stats = self.baseline_stats[col]
            mean = stats['mean']
            std = stats['std']

            if std == 0:
                continue

            z_score = abs((value - mean) / std)

            if z_score > 2.0:
                desc = self.FEATURE_DESCRIPTIONS.get(col, col)
                deviations.append({
                    'feature': col,
                    'description': desc,
                    'value': value,
                    'mean': mean,
                    'std': std,
                    'z_score': z_score,
                })

        # Sort by z-score (most anomalous first)
        deviations.sort(key=lambda d: d['z_score'], reverse=True)

        # Build explanation string
        if score is not None:
            header = f"ANOMALY SCORE: {score:.0f}/100"
        else:
            header = "ANOMALY ANALYSIS"

        if not deviations:
            return f"{header} | No significantly unusual features detected."

        factors = []
        for d in deviations[:5]:  # Top 5 most unusual features
            factors.append(
                f"{d['description']}: {d['value']:.2f} "
                f"(baseline: {d['mean']:.2f}±{d['std']:.2f}, z={d['z_score']:.1f})"
            )

        return f"{header} | Unusual factors: " + "; ".join(factors)

    def save_model(self, path: Optional[str] = None):
        """Save trained models, scaler, and statistics to disk."""
        if path is None:
            project_root = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))
            path = os.path.join(project_root, 'models')

        os.makedirs(path, exist_ok=True)

        model_data = {
            'models': self.models,
            'scaler': self.scaler,
            'baseline_stats': self.baseline_stats,
            'score_ranges': self._score_ranges,
            'feature_columns': self.FEATURE_COLUMNS,
        }

        model_path = os.path.join(path, 'ml_ensemble.joblib')
        joblib.dump(model_data, model_path)
        print(f"  ✓ Model saved to: {model_path}")

    def load_model(self, path: Optional[str] = None):
        """Load trained models from disk."""
        if path is None:
            project_root = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))
            path = os.path.join(project_root, 'models')

        model_path = os.path.join(path, 'ml_ensemble.joblib')
        model_data = joblib.load(model_path)

        self.models = model_data['models']
        self.scaler = model_data['scaler']
        self.baseline_stats = model_data['baseline_stats']
        self._score_ranges = model_data['score_ranges']
        self.is_trained = True
        print(f"  ✓ Model loaded from: {model_path}")


# ─────────────────────── Main ─────────────────────────────────

def main():
    """Train the ML ensemble and score the full dataset."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(project_root, "data")

    feature_path = os.path.join(data_dir, "feature_matrix.csv")
    if not os.path.exists(feature_path):
        print("[!] Feature matrix not found. Run feature_engineering.py first.")
        sys.exit(1)

    print("=" * 70)
    print("  LOLBins Detection Engine — ML Anomaly Scorer")
    print("=" * 70)

    # Load feature matrix
    print("\n[1/5] Loading feature matrix...")
    df = pd.read_csv(feature_path)
    print(f"    ✓ Loaded {len(df)} events with {len(df.columns)} columns")

    # Split into benign-only for training
    print("\n[2/5] Splitting benign baseline for training...")
    benign_df = df[df['label'] == 'benign'].copy()
    print(f"    ✓ Benign training set: {len(benign_df)} events")

    # Train ensemble
    print("\n[3/5] Training ML ensemble...")
    scorer = MLAnomalyScorer()
    scorer.train(benign_df)

    # Score full dataset
    print("\n[4/5] Scoring full dataset...")
    scores = scorer.score(df)
    df['ml_anomaly_score'] = scores

    # Save model
    scorer.save_model()

    # Save scored dataset
    output_path = os.path.join(data_dir, "ml_scored_dataset.csv")
    df.to_csv(output_path, index=False)
    print(f"  ✓ Scored dataset saved to: {output_path}")

    # Print statistics
    print("\n" + "=" * 70)
    print("  ML SCORING RESULTS")
    print("=" * 70)

    for label_name in ['benign', 'malicious', 'gray_area']:
        subset = df[df['label'] == label_name]
        if len(subset) > 0:
            scores_subset = subset['ml_anomaly_score']
            print(f"\n  {label_name.upper()} ({len(subset)} events):")
            print(f"    Mean score:   {scores_subset.mean():.1f}")
            print(f"    Median score: {scores_subset.median():.1f}")
            print(f"    Std dev:      {scores_subset.std():.1f}")
            print(f"    Min/Max:      {scores_subset.min():.1f} / {scores_subset.max():.1f}")
            high_alerts = (scores_subset > 70).sum()
            print(f"    Events > 70:  {high_alerts} ({high_alerts/len(subset)*100:.1f}%)")

    # Print top 10 highest-scoring events with explanations
    print("\n  TOP 10 HIGHEST SCORING EVENTS:")
    print("  " + "-" * 68)
    top_10 = df.nlargest(10, 'ml_anomaly_score')
    for idx, (_, row) in enumerate(top_10.iterrows(), 1):
        image = os.path.basename(str(row.get('Image', 'unknown')))
        parent = os.path.basename(str(row.get('ParentImage', 'unknown')))
        label = row.get('label', 'unknown')
        score_val = row['ml_anomaly_score']
        explanation = scorer.explain(row, score_val)
        print(f"\n  #{idx} [{label:10s}] {parent} → {image}")
        print(f"     {explanation}")

    print("\n" + "=" * 70)
    print("  ML scoring complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
