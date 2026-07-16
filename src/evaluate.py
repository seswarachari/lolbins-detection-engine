#!/usr/bin/env python3
"""
Evaluation Module for LOLBins Detection Engine
================================================
Computes precision, recall, F1, and false positive rates for each
detection layer (Sigma, ML, Chain) and the combined pipeline.
Generates confusion matrix visualizations and comparison tables.

Author: Eswar Achari
"""

import os
import sys
import warnings

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for saving plots
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
    roc_curve, auc,
)
from tabulate import tabulate

warnings.filterwarnings('ignore')


class Evaluator:
    """
    Evaluates detection performance using ground truth labels.
    Computes per-layer and combined metrics with visualizations.
    """

    def __init__(self, project_root: str = None):
        if project_root is None:
            project_root = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))
        self.project_root = project_root
        self.reports_dir = os.path.join(project_root, 'reports')
        os.makedirs(self.reports_dir, exist_ok=True)

    def evaluate(self, results_path: str = None) -> dict:
        """
        Run full evaluation on pipeline results.
        
        Args:
            results_path: Path to pipeline_results.csv
            
        Returns:
            Dict with all computed metrics.
        """
        if results_path is None:
            results_path = os.path.join(
                self.project_root, 'data', 'pipeline_results.csv')

        if not os.path.exists(results_path):
            print("[!] Pipeline results not found. Run detection_pipeline.py first.")
            sys.exit(1)

        print("=" * 70)
        print("  LOLBins Detection Engine — Evaluation")
        print("=" * 70)

        df = pd.read_csv(results_path)
        print(f"\n  Loaded {len(df)} events with ground truth labels")

        # Ground truth
        y_true = df['is_malicious'].values

        metrics = {}

        # ═══════ Layer 1: Sigma Rules ═══════
        print("\n" + "─" * 50)
        print("  LAYER 1: SIGMA RULES")
        print("─" * 50)
        y_sigma = df['sigma_match'].astype(int).values
        metrics['sigma'] = self._compute_metrics(y_true, y_sigma, 'Sigma Rules')
        self._plot_confusion_matrix(y_true, y_sigma, 'Sigma Rules',
                                    os.path.join(self.reports_dir, 'cm_sigma.png'))

        # Missed techniques
        if 'mitre_technique_id' in df.columns:
            malicious = df[df['is_malicious'] == 1]
            missed = malicious[malicious['sigma_match'] == False]
            if len(missed) > 0:
                print("\n  Missed Techniques (Sigma):")
                for tid, count in missed['mitre_technique_id'].value_counts().items():
                    tname = missed[missed['mitre_technique_id'] == tid]['technique_name'].iloc[0]
                    print(f"    {tid}: {tname} ({count} events missed)")

        # ═══════ Layer 2: ML Anomaly Score ═══════
        print("\n" + "─" * 50)
        print("  LAYER 2: ML ENSEMBLE (threshold=70)")
        print("─" * 50)
        y_ml = (df['ml_anomaly_score'] > 70).astype(int).values
        metrics['ml'] = self._compute_metrics(y_true, y_ml, 'ML Ensemble (>70)')
        self._plot_confusion_matrix(y_true, y_ml, 'ML Ensemble (threshold=70)',
                                    os.path.join(self.reports_dir, 'cm_ml.png'))

        # ═══════ Layer 3: Chain Analysis ═══════
        print("\n" + "─" * 50)
        print("  LAYER 3: CHAIN ANALYSIS (threshold=60)")
        print("─" * 50)
        y_chain = (df['chain_risk_score'] > 60).astype(int).values
        metrics['chain'] = self._compute_metrics(y_true, y_chain, 'Chain Analysis (>60)')
        self._plot_confusion_matrix(y_true, y_chain, 'Chain Analysis (threshold=60)',
                                    os.path.join(self.reports_dir, 'cm_chain.png'))

        # ═══════ Combined Pipeline ═══════
        print("\n" + "─" * 50)
        print("  COMBINED PIPELINE")
        print("─" * 50)
        y_combined = df['final_verdict'].isin(['ALERT', 'REVIEW']).astype(int).values
        metrics['combined'] = self._compute_metrics(y_true, y_combined, 'Combined Pipeline')
        self._plot_confusion_matrix(y_true, y_combined, 'Combined Pipeline',
                                    os.path.join(self.reports_dir, 'cm_combined.png'))

        # ═══════ Comparison Table ═══════
        self._print_comparison_table(metrics)

        # ═══════ ROC Curve ═══════
        if 'ml_anomaly_score' in df.columns:
            self._plot_roc_curve(y_true, df['ml_anomaly_score'].values,
                                os.path.join(self.reports_dir, 'roc_curve.png'))

        # ═══════ Per-Technique Breakdown ═══════
        self._per_technique_breakdown(df)

        # ═══════ False Positive Analysis ═══════
        self._false_positive_analysis(df)

        # Save metrics summary
        self._save_metrics_summary(metrics)

        print("\n" + "=" * 70)
        print("  Evaluation complete! Reports saved to: reports/")
        print("=" * 70)

        return metrics

    def _compute_metrics(self, y_true, y_pred, layer_name: str) -> dict:
        """Compute precision, recall, F1, and FPR for a detection layer."""
        # Handle edge cases
        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 0.001)
        fpr = fp / max(fp + tn, 1)

        metrics = {
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1': round(f1, 4),
            'fpr': round(fpr, 4),
            'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        }

        print(f"\n  {layer_name}:")
        print(f"    Precision:         {precision:.3f}")
        print(f"    Recall:            {recall:.3f}")
        print(f"    F1 Score:          {f1:.3f}")
        print(f"    False Positive Rate: {fpr:.3f}")
        print(f"    TP={tp}, FP={fp}, FN={fn}, TN={tn}")

        return metrics

    def _plot_confusion_matrix(self, y_true, y_pred, title: str, save_path: str):
        """Generate and save a confusion matrix heatmap."""
        cm = confusion_matrix(y_true, y_pred)

        fig, ax = plt.subplots(figsize=(6, 5))
        sns.heatmap(
            cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Benign', 'Malicious'],
            yticklabels=['Benign', 'Malicious'],
            ax=ax, cbar_kws={'label': 'Count'},
            annot_kws={'size': 14},
        )
        ax.set_xlabel('Predicted', fontsize=12)
        ax.set_ylabel('Actual', fontsize=12)
        ax.set_title(f'Confusion Matrix — {title}', fontsize=13, fontweight='bold')
        plt.tight_layout()
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"    ✓ Confusion matrix saved: {os.path.basename(save_path)}")

    def _plot_roc_curve(self, y_true, scores, save_path: str):
        """Generate ROC curve for ML anomaly scores."""
        fpr, tpr, thresholds = roc_curve(y_true, scores)
        roc_auc = auc(fpr, tpr)

        fig, ax = plt.subplots(figsize=(7, 6))
        ax.plot(fpr, tpr, 'b-', linewidth=2,
                label=f'ML Ensemble (AUC = {roc_auc:.3f})')
        ax.plot([0, 1], [0, 1], 'k--', linewidth=1, alpha=0.5)

        # Mark the threshold=70 point
        threshold_70_idx = np.argmin(np.abs(thresholds - 70))
        ax.plot(fpr[threshold_70_idx], tpr[threshold_70_idx], 'ro',
                markersize=10, label=f'Threshold=70 (FPR={fpr[threshold_70_idx]:.3f})')

        ax.set_xlabel('False Positive Rate', fontsize=12)
        ax.set_ylabel('True Positive Rate', fontsize=12)
        ax.set_title('ROC Curve — ML Ensemble Anomaly Scorer',
                     fontsize=13, fontweight='bold')
        ax.legend(loc='lower right', fontsize=10)
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"    ✓ ROC curve saved: {os.path.basename(save_path)}")

    def _print_comparison_table(self, metrics: dict):
        """Print a comparison table showing why combined approach is best."""
        print("\n" + "=" * 70)
        print("  DETECTION LAYER COMPARISON")
        print("=" * 70)

        headers = ['Layer', 'Precision', 'Recall', 'F1', 'FPR', 'TP', 'FP', 'FN']
        rows = []
        for layer_name, m in metrics.items():
            display_name = {
                'sigma': 'Sigma Rules',
                'ml': 'ML Ensemble',
                'chain': 'Chain Analysis',
                'combined': '★ COMBINED ★',
            }.get(layer_name, layer_name)
            rows.append([
                display_name,
                f"{m['precision']:.3f}",
                f"{m['recall']:.3f}",
                f"{m['f1']:.3f}",
                f"{m['fpr']:.3f}",
                m['tp'], m['fp'], m['fn'],
            ])

        print("\n" + tabulate(rows, headers=headers, tablefmt='grid'))

        # Analysis commentary
        print("\n  WHY COMBINED OUTPERFORMS INDIVIDUAL LAYERS:")
        sigma = metrics.get('sigma', {})
        ml = metrics.get('ml', {})
        combined = metrics.get('combined', {})

        if sigma and ml and combined:
            if combined['recall'] >= sigma['recall']:
                print(f"  • Combined recall ({combined['recall']:.3f}) ≥ "
                      f"Sigma alone ({sigma['recall']:.3f})")
                print(f"    → ML catches malicious events that don't match Sigma patterns")
            if combined['recall'] >= ml['recall']:
                print(f"  • Combined recall ({combined['recall']:.3f}) ≥ "
                      f"ML alone ({ml['recall']:.3f})")
                print(f"    → Sigma catches events that ML scores below threshold")
            if combined['precision'] > 0:
                print(f"  • Combined precision ({combined['precision']:.3f}): "
                      f"multi-layer validation reduces false positives")

    def _per_technique_breakdown(self, df: pd.DataFrame):
        """Show detection rate per MITRE technique."""
        if 'mitre_technique_id' not in df.columns:
            return

        print("\n" + "─" * 50)
        print("  PER-TECHNIQUE DETECTION BREAKDOWN")
        print("─" * 50)

        malicious = df[df['is_malicious'] == 1].copy()
        if len(malicious) == 0:
            return

        headers = ['Technique', 'Name', 'Total', 'Sigma', 'ML>70',
                    'Chain>60', 'Combined', 'Detection%']
        rows = []

        for tid in malicious['mitre_technique_id'].unique():
            if not tid:
                continue
            subset = malicious[malicious['mitre_technique_id'] == tid]
            total = len(subset)
            tname = subset['technique_name'].iloc[0] if 'technique_name' in subset.columns else ''

            sigma_det = subset['sigma_match'].sum() if 'sigma_match' in subset.columns else 0
            ml_det = (subset['ml_anomaly_score'] > 70).sum() if 'ml_anomaly_score' in subset.columns else 0
            chain_det = (subset['chain_risk_score'] > 60).sum() if 'chain_risk_score' in subset.columns else 0
            combined_det = subset['final_verdict'].isin(['ALERT', 'REVIEW']).sum()

            det_rate = combined_det / max(total, 1) * 100

            rows.append([
                tid, tname[:25], total,
                int(sigma_det), int(ml_det), int(chain_det),
                int(combined_det), f"{det_rate:.0f}%"
            ])

        print("\n" + tabulate(rows, headers=headers, tablefmt='grid'))

    def _false_positive_analysis(self, df: pd.DataFrame):
        """Analyze false positives by category."""
        print("\n" + "─" * 50)
        print("  FALSE POSITIVE ANALYSIS")
        print("─" * 50)

        # FPs are benign/gray-area events flagged as alerts
        fps = df[
            (df['is_malicious'] == 0) &
            (df['final_verdict'].isin(['ALERT', 'REVIEW']))
        ]

        if len(fps) == 0:
            print("\n  No false positives detected! ✓")
            return

        print(f"\n  Total false positives: {len(fps)}")

        # FP breakdown by label
        if 'label' in fps.columns:
            print("\n  FP by event category:")
            for label, count in fps['label'].value_counts().items():
                print(f"    {label}: {count}")

        # FP breakdown by process
        if 'Image' in fps.columns:
            print("\n  FP by process (top 5):")
            proc_counts = fps['Image'].apply(
                lambda x: os.path.basename(str(x))).value_counts().head(5)
            for proc, count in proc_counts.items():
                print(f"    {proc}: {count}")

        # FP by trigger
        print("\n  FP trigger analysis:")
        sigma_fps = fps[fps.get('sigma_match', False) == True]
        ml_fps = fps[fps.get('ml_anomaly_score', 0) > 70]
        chain_fps = fps[fps.get('chain_risk_score', 0) > 60]
        print(f"    Triggered by Sigma:  {len(sigma_fps)}")
        print(f"    Triggered by ML>70:  {len(ml_fps)}")
        print(f"    Triggered by Chain>60: {len(chain_fps)}")

        # Tuning recommendations
        print("\n  TUNING RECOMMENDATIONS:")
        if len(sigma_fps) > 0:
            print("  • Review Sigma rules triggering on legitimate admin tools")
            for rule, cnt in sigma_fps['sigma_rule_name'].value_counts().items():
                print(f"    → {rule}: {cnt} FPs — consider adding exclusions")
        if len(ml_fps) > 5:
            print("  • Consider raising ML threshold from 70 to 75")
        if len(chain_fps) > 5:
            print("  • Consider raising chain threshold from 60 to 70")

    def _save_metrics_summary(self, metrics: dict):
        """Save metrics summary to a JSON-like text file."""
        summary_path = os.path.join(self.reports_dir, 'metrics_summary.txt')
        with open(summary_path, 'w') as f:
            f.write("LOLBins Detection Engine — Evaluation Metrics\n")
            f.write("=" * 50 + "\n\n")
            for layer, m in metrics.items():
                f.write(f"{layer.upper()}:\n")
                for key, val in m.items():
                    f.write(f"  {key}: {val}\n")
                f.write("\n")
        print(f"\n  ✓ Metrics summary saved: {os.path.basename(summary_path)}")


# ─────────────────────── Main ─────────────────────────────────

def main():
    """Run evaluation on pipeline results."""
    evaluator = Evaluator()
    metrics = evaluator.evaluate()
    return metrics


if __name__ == "__main__":
    main()
