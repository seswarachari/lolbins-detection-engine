#!/usr/bin/env python3
"""
Combined Detection Pipeline for LOLBins Detection Engine
==========================================================
Orchestrates the multi-layer detection architecture:
1. Sigma Rule Engine (deterministic pattern matching)
2. ML Ensemble Anomaly Scorer (statistical anomaly detection)
3. Behavioral Chain Analyzer (process ancestry patterns)

Fuses results with weighted confidence scoring to produce
prioritized alerts with explainability narratives.

Author: Eswar Achari
"""

import os
import sys
from typing import Optional

import pandas as pd
import numpy as np
from tabulate import tabulate

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.feature_engineering import FeatureEngineer
from src.sigma_engine import SigmaEngine
from src.ml_anomaly_scorer import MLAnomalyScorer
from src.chain_analyzer import ChainAnalyzer


class DetectionPipeline:
    """
    Multi-layer detection pipeline that fuses Sigma rules, ML anomaly scores,
    and behavioral chain analysis into prioritized security alerts.
    
    Classification Logic:
    ┌─────────────────────────────────────────────────────────┐
    │ Sigma Match                  → CRITICAL  (90-100)       │
    │ Chain Match (>60) + ML >70   → HIGH      (75-89)        │
    │ ML Score >70                 → MEDIUM    (50-74)        │
    │ Chain Match (>60)            → LOW       (30-49)        │
    │ No detections                → CLEAR     (0-29)         │
    └─────────────────────────────────────────────────────────┘
    """

    def __init__(self, project_root: Optional[str] = None):
        """
        Initialize all detection layers.
        
        Args:
            project_root: Path to project root directory.
        """
        if project_root is None:
            project_root = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))
        self.project_root = project_root
        self.data_dir = os.path.join(project_root, "data")

        # Initialize detection layers
        print("\n[*] Initializing detection layers...")

        # Layer 1: Sigma Engine
        print("  Loading Sigma rules...")
        self.sigma_engine = SigmaEngine()

        # Layer 2: ML Anomaly Scorer
        print("  Loading ML ensemble...")
        self.ml_scorer = MLAnomalyScorer()
        model_path = os.path.join(project_root, 'models')
        if os.path.exists(os.path.join(model_path, 'ml_ensemble.joblib')):
            self.ml_scorer.load_model(model_path)
        else:
            print("  [!] ML model not found — will train during pipeline run")

        # Layer 3: Chain Analyzer
        print("  Loading Chain Analyzer...")
        self.chain_analyzer = ChainAnalyzer()

        # Feature Engineer
        benign_path = os.path.join(self.data_dir, "benign_baseline.csv")
        self.feature_engineer = FeatureEngineer(
            benign_baseline_path=benign_path)

    def run(self, input_path: Optional[str] = None,
            output_dir: Optional[str] = None) -> pd.DataFrame:
        """
        Run the full detection pipeline on a dataset.
        
        Args:
            input_path: Path to input CSV. Defaults to data/full_dataset.csv.
            output_dir: Path for output files. Defaults to data/.
            
        Returns:
            DataFrame with all detection results and final verdicts.
        """
        if input_path is None:
            input_path = os.path.join(self.data_dir, "full_dataset.csv")
        if output_dir is None:
            output_dir = self.data_dir

        print("\n" + "=" * 70)
        print("  LOLBins Detection Engine — Full Pipeline")
        print("=" * 70)

        # Step 1: Load data
        print("\n[1/6] Loading event data...")
        df = pd.read_csv(input_path)
        print(f"    ✓ Loaded {len(df)} events")

        # Step 2: Feature engineering
        print("\n[2/6] Extracting features...")
        df_features = self.feature_engineer.extract_features(df)
        print(f"    ✓ Extracted {len(self.feature_engineer.get_feature_columns())} features")

        # Step 3: Sigma rule evaluation
        print("\n[3/6] Running Sigma rule engine...")
        df_sigma = self.sigma_engine.evaluate_dataset(df_features)
        sigma_hits = df_sigma['sigma_match'].sum()
        print(f"    ✓ Sigma matches: {sigma_hits}")

        # Step 4: ML anomaly scoring
        print("\n[4/6] Running ML anomaly scorer...")
        if not self.ml_scorer.is_trained:
            print("    Training ML models on benign baseline...")
            benign_features = df_features[df_features['label'] == 'benign']
            self.ml_scorer.train(benign_features)
            self.ml_scorer.save_model()

        ml_scores = self.ml_scorer.score(df_features)
        df_sigma['ml_anomaly_score'] = ml_scores
        ml_alerts = (ml_scores > 70).sum()
        print(f"    ✓ ML anomaly alerts (>70): {ml_alerts}")

        # Step 5: Chain analysis
        print("\n[5/6] Running behavioral chain analysis...")
        df_chain = self.chain_analyzer.analyze_dataset(df_sigma)
        chain_alerts = (df_chain['chain_risk_score'] > 60).sum()
        print(f"    ✓ Chain risk alerts (>60): {chain_alerts}")

        # Step 6: Fuse results
        print("\n[6/6] Fusing detection layers...")
        df_final = self._fuse_results(df_chain)

        # Save outputs
        self._save_results(df_final, output_dir)

        # Print summary
        self._print_summary(df_final)

        return df_final

    def _fuse_results(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Fuse all detection layer results into final verdicts.
        
        Priority levels (highest to lowest):
        - CRITICAL: Sigma rule matched
        - HIGH: Chain match + ML anomaly  
        - MEDIUM: ML anomaly only
        - LOW: Chain match only
        - CLEAR: No detections
        """
        verdicts = []
        priorities = []
        confidences = []
        explanations = []

        for idx, row in df.iterrows():
            sigma_match = row.get('sigma_match', False)
            ml_score = row.get('ml_anomaly_score', 0)
            chain_score = row.get('chain_risk_score', 0)

            # Determine verdict based on fusion logic
            if sigma_match:
                verdict = "ALERT"
                priority = "CRITICAL"
                confidence = min(90 + (ml_score / 10), 100)
                explanation = (
                    f"Sigma rule matched: {row.get('sigma_rule_name', 'Unknown')} | "
                    f"ML Score: {ml_score:.0f} | Chain Risk: {chain_score:.0f}"
                )
            elif chain_score > 60 and ml_score > 70:
                verdict = "ALERT"
                priority = "HIGH"
                confidence = 75 + min((ml_score - 70) / 3 + (chain_score - 60) / 4, 14)
                explanation = (
                    f"Chain + ML anomaly detected | "
                    f"ML Score: {ml_score:.0f} | Chain: {row.get('chain_description', '')}"
                )
            elif ml_score > 70:
                verdict = "ALERT"
                priority = "MEDIUM"
                confidence = 50 + min((ml_score - 70) / 1.5, 24)
                # Generate ML explanation
                try:
                    ml_explain = self.ml_scorer.explain(row, ml_score)
                except Exception:
                    ml_explain = f"ML anomaly score: {ml_score:.0f}"
                explanation = ml_explain
            elif chain_score > 60:
                verdict = "REVIEW"
                priority = "LOW"
                confidence = 30 + min((chain_score - 60) / 2, 19)
                explanation = (
                    f"Suspicious chain detected | "
                    f"Chain: {row.get('chain_description', '')}"
                )
            else:
                verdict = "CLEAR"
                priority = "NONE"
                confidence = max(0, ml_score / 3)
                explanation = ""

            verdicts.append(verdict)
            priorities.append(priority)
            confidences.append(round(confidence, 1))
            explanations.append(explanation)

        df['final_verdict'] = verdicts
        df['priority'] = priorities
        df['confidence'] = confidences
        df['explanation'] = explanations

        return df

    def _save_results(self, df: pd.DataFrame, output_dir: str):
        """Save pipeline results to CSV."""
        os.makedirs(output_dir, exist_ok=True)

        # Full results
        full_path = os.path.join(output_dir, "pipeline_results.csv")
        df.to_csv(full_path, index=False)
        print(f"\n  ✓ Full results: {full_path}")

        # Alerts only
        alerts = df[df['final_verdict'].isin(['ALERT', 'REVIEW'])]
        alerts_path = os.path.join(output_dir, "alerts.csv")
        alerts.to_csv(alerts_path, index=False)
        print(f"  ✓ Alerts only ({len(alerts)} events): {alerts_path}")

    def _print_summary(self, df: pd.DataFrame):
        """Print a formatted pipeline results summary."""
        print("\n" + "=" * 70)
        print("  DETECTION PIPELINE RESULTS")
        print("=" * 70)

        # Overall statistics
        total = len(df)
        alerts = df[df['final_verdict'] == 'ALERT']
        reviews = df[df['final_verdict'] == 'REVIEW']
        clears = df[df['final_verdict'] == 'CLEAR']

        print(f"\n  Total events processed: {total}")
        print(f"  Alerts:                 {len(alerts)} ({len(alerts)/total*100:.1f}%)")
        print(f"  Reviews:                {len(reviews)} ({len(reviews)/total*100:.1f}%)")
        print(f"  Clear:                  {len(clears)} ({len(clears)/total*100:.1f}%)")

        # Priority breakdown
        print("\n  Alert Priority Breakdown:")
        for priority in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = len(df[df['priority'] == priority])
            if count > 0:
                print(f"    {priority:10s}: {count:3d}")

        # Detection accuracy (if labels available)
        if 'is_malicious' in df.columns:
            print("\n  Detection vs Ground Truth:")
            true_pos = len(alerts[alerts['is_malicious'] == 1])
            false_pos = len(alerts[alerts['is_malicious'] == 0])
            true_mal = len(df[df['is_malicious'] == 1])
            detected_mal = len(df[(df['is_malicious'] == 1) &
                                  (df['final_verdict'].isin(['ALERT', 'REVIEW']))])
            print(f"    True positives:  {true_pos}")
            print(f"    False positives: {false_pos}")
            print(f"    Malicious caught: {detected_mal}/{true_mal} "
                  f"({detected_mal/max(true_mal,1)*100:.1f}%)")

        # Print alerts table
        if len(alerts) > 0:
            print("\n  ALERTS TABLE (top 20):")
            print("  " + "-" * 68)

            alert_table = alerts.head(20)[[
                'UtcTime', 'priority', 'sigma_rule_name',
                'ml_anomaly_score', 'confidence',
            ]].copy()

            # Truncate columns for display
            alert_table['UtcTime'] = alert_table['UtcTime'].str[:19]

            print(tabulate(
                alert_table,
                headers=['Timestamp', 'Priority', 'Sigma Rule',
                         'ML Score', 'Confidence'],
                tablefmt='simple',
                showindex=False,
                floatfmt='.1f',
            ))

        print("\n" + "=" * 70)
        print("  Pipeline complete!")
        print("=" * 70)


# ─────────────────────── Main ─────────────────────────────────

def main():
    """Run the full detection pipeline."""
    pipeline = DetectionPipeline()
    df_results = pipeline.run()
    return df_results


if __name__ == "__main__":
    main()
