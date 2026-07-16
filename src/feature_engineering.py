#!/usr/bin/env python3
"""
Feature Engineering Module for LOLBins Detection Engine
========================================================
Extracts 29 behavioral features from Sysmon Event ID 1 process creation events.
Features span process identity, command line analysis, chain analysis,
temporal patterns, statistical baselines, and user context.

Shannon entropy is implemented from scratch (no external entropy library).

Author: Eswar Achari
"""

import os
import sys
import json
import math
import re
import hashlib
from collections import Counter
from typing import Dict, Optional

import pandas as pd
import numpy as np


class FeatureEngineer:
    """
    Extracts 29 behavioral features from process creation events for
    downstream anomaly detection and rule matching.
    
    Design Decision: Features are chosen to capture the behavioral
    differences between legitimate LOLBin usage and malicious abuse:
    - Process identity reveals WHAT is running
    - Command line analysis reveals HOW it's being used
    - Chain analysis reveals the execution CONTEXT
    - Temporal features reveal WHEN it happens
    - Statistical features reveal how UNUSUAL it is vs. baseline
    """

    # ───────────── Known binary classifications ─────────────
    LOLBIN_LIST = [
        'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
        'cscript.exe', 'wscript.exe', 'bitsadmin.exe', 'msbuild.exe',
        'installutil.exe', 'powershell.exe', 'cmd.exe',
    ]

    SCRIPTING_ENGINES = [
        'powershell.exe', 'cmd.exe', 'cscript.exe', 'wscript.exe', 'mshta.exe',
    ]

    OFFICE_APPS = [
        'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
    ]

    BROWSERS = [
        'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
    ]

    ROOT_PROCESSES = [
        'explorer.exe', 'services.exe', 'svchost.exe', 'system',
        'wininit.exe', 'csrss.exe', 'smss.exe',
    ]

    # Suspicious command line indicators commonly seen in LOLBin abuse
    SUSPICIOUS_FLAGS = [
        '-enc', '-nop', '-w hidden', '-windowstyle hidden',
        '/i:http', '-urlcache', 'javascript:', 'encodedcommand',
        '-decode', '-encode', '/transfer', '//e:jscript',
        '//e:vbscript', '-split -f', '-ep bypass', '-exec bypass',
        '-noni', 'downloadstring', 'downloadfile', 'invoke-expression',
        'iex(', 'hidden', '-noprofile',
    ]

    def __init__(self, benign_baseline_path: Optional[str] = None):
        """
        Initialize the feature engineer.
        
        Args:
            benign_baseline_path: Path to benign baseline CSV. If provided,
                computes baseline statistics for relative features (z-scores,
                pair rarity). This is critical for the ML layer — anomaly
                scores are only meaningful relative to a known-good baseline.
        """
        self.baseline_stats = {
            'command_line_length': {'mean': 0, 'std': 1},
            'command_line_entropy': {'mean': 0, 'std': 1},
        }
        self.pair_frequencies = {}
        self.total_baseline_events = 0
        self.label_encoders = {}
        self._label_encoder_fitted = False

        if benign_baseline_path and os.path.exists(benign_baseline_path):
            self._compute_baseline(benign_baseline_path)

    def _compute_baseline(self, path: str):
        """
        Compute baseline statistics from benign data for relative features.
        This establishes what "normal" looks like so anomalies can be measured.
        """
        print(f"  [*] Computing baseline statistics from: {os.path.basename(path)}")
        df = pd.read_csv(path)
        self.total_baseline_events = len(df)

        # Command line length statistics
        lengths = df['CommandLine'].fillna('').str.len()
        self.baseline_stats['command_line_length'] = {
            'mean': float(lengths.mean()),
            'std': float(max(lengths.std(), 1.0)),  # Avoid division by zero
        }

        # Command line entropy statistics
        entropies = df['CommandLine'].fillna('').apply(self.shannon_entropy)
        self.baseline_stats['command_line_entropy'] = {
            'mean': float(entropies.mean()),
            'std': float(max(entropies.std(), 0.1)),
        }

        # Parent→child pair frequency distribution
        # This is key: rare parent→child combos in the baseline are suspicious
        pairs = df.apply(
            lambda row: (
                self._get_basename(row.get('ParentImage', '')),
                self._get_basename(row.get('Image', ''))
            ), axis=1
        )
        pair_counts = Counter(pairs)
        total = sum(pair_counts.values())
        self.pair_frequencies = {
            f"{p}>{c}": count / total
            for (p, c), count in pair_counts.items()
        }

        print(f"    ✓ Baseline: {self.total_baseline_events} events, "
              f"{len(self.pair_frequencies)} unique parent→child pairs")

    @staticmethod
    def _get_basename(image_path: str) -> str:
        """Extract lowercase basename from a Windows image path."""
        if not image_path or pd.isna(image_path):
            return 'unknown'
        # Handle both forward and backslash paths
        basename = image_path.replace('/', '\\').split('\\')[-1]
        return basename.lower()

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """
        Compute Shannon entropy of a string from scratch.
        
        Shannon entropy measures the randomness/information density of a string.
        High entropy (>4.5) in command lines often indicates obfuscation,
        encoding, or encrypted payloads — common in LOLBin abuse.
        
        Formula: H(X) = -Σ p(x) * log2(p(x))
        
        Args:
            text: Input string to compute entropy for.
            
        Returns:
            Shannon entropy value (bits per character). Range: 0 to ~7+
            0 = perfectly uniform (e.g., "aaaa")
            Higher = more random/complex
        """
        if not text or not isinstance(text, str):
            return 0.0

        # Count character frequencies
        freq = Counter(text)
        length = len(text)

        # Compute entropy using Shannon's formula
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract all 29 features from process creation events.
        
        Args:
            df: DataFrame with Sysmon Event ID 1 columns.
            
        Returns:
            DataFrame with original columns + 29 feature columns.
        """
        result = df.copy()

        # Ensure string columns are strings (handle NaN)
        str_cols = ['Image', 'CommandLine', 'ParentImage', 'ParentCommandLine',
                    'User', 'IntegrityLevel', 'UtcTime']
        for col in str_cols:
            if col in result.columns:
                result[col] = result[col].fillna('').astype(str)

        # Pre-compute basenames for efficiency
        result['_child_basename'] = result['Image'].apply(self._get_basename)
        result['_parent_basename'] = result['ParentImage'].apply(self._get_basename)
        result['_cmdline_lower'] = result['CommandLine'].str.lower()

        # ═══════════ Process Identity Features (4) ═══════════
        result['parent_process_name'] = self._label_encode(
            result['_parent_basename'], 'parent_process')
        result['child_process_name'] = self._label_encode(
            result['_child_basename'], 'child_process')
        result['is_known_lolbin'] = result['_child_basename'].isin(
            self.LOLBIN_LIST).astype(int)
        result['is_scripting_engine'] = result['_child_basename'].isin(
            self.SCRIPTING_ENGINES).astype(int)

        # ═══════════ Command Line Analysis Features (10) ═══════════
        result['command_line_length'] = result['CommandLine'].str.len()
        result['command_line_entropy'] = result['CommandLine'].apply(
            self.shannon_entropy)
        result['has_suspicious_flag'] = result['_cmdline_lower'].apply(
            self._check_suspicious_flags).astype(int)
        result['contains_url'] = result['CommandLine'].apply(
            lambda x: 1 if re.search(r'https?://', str(x), re.IGNORECASE) else 0)
        result['contains_ip_address'] = result['CommandLine'].apply(
            lambda x: 1 if re.search(
                r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', str(x)) else 0)
        result['has_base64_pattern'] = result['CommandLine'].apply(
            lambda x: 1 if re.search(
                r'[A-Za-z0-9+/]{40,}={0,2}', str(x)) else 0)
        result['argument_count'] = result['CommandLine'].apply(
            lambda x: len(str(x).split()))
        result['suspicious_argument_ratio'] = result.apply(
            self._calc_suspicious_ratio, axis=1)
        result['has_encoded_command'] = result['_cmdline_lower'].apply(
            lambda x: 1 if ('-enc ' in x or '-enc\t' in x or
                           x.endswith('-enc') or
                           '-encodedcommand' in x) else 0)
        result['has_download_indicator'] = result['_cmdline_lower'].apply(
            lambda x: 1 if any(ind in x for ind in [
                'urlcache', '/transfer', 'download', 'invoke-webrequest',
                'wget', 'curl', 'downloadstring', 'downloadfile',
            ]) else 0)

        # ═══════════ Chain Analysis Features (5) ═══════════
        result['process_ancestry_depth'] = result['_parent_basename'].apply(
            self._estimate_depth)
        result['parent_is_office_app'] = result['_parent_basename'].isin(
            self.OFFICE_APPS).astype(int)
        result['parent_is_browser'] = result['_parent_basename'].isin(
            self.BROWSERS).astype(int)
        result['parent_is_script_engine'] = result['_parent_basename'].isin(
            self.SCRIPTING_ENGINES).astype(int)
        result['chain_hash'] = result.apply(
            lambda row: int(hashlib.md5(
                f"{row['_parent_basename']}>{row['_child_basename']}".encode()
            ).hexdigest()[:8], 16), axis=1)

        # ═══════════ Temporal Features (4) ═══════════
        timestamps = pd.to_datetime(result['UtcTime'], errors='coerce')
        result['hour_of_day'] = timestamps.dt.hour.fillna(12).astype(int)
        result['is_off_hours'] = ((result['hour_of_day'] >= 0) &
                                  (result['hour_of_day'] <= 5)).astype(int)
        result['is_weekend'] = timestamps.dt.dayofweek.fillna(0).isin(
            [5, 6]).astype(int)
        result['minute_of_hour'] = timestamps.dt.minute.fillna(0).astype(int)

        # ═══════════ Statistical Features (3) ═══════════
        result['parent_child_pair_rarity'] = result.apply(
            self._calc_pair_rarity, axis=1)
        result['command_length_zscore'] = (
            (result['command_line_length'] -
             self.baseline_stats['command_line_length']['mean']) /
            self.baseline_stats['command_line_length']['std']
        )
        result['entropy_zscore'] = (
            (result['command_line_entropy'] -
             self.baseline_stats['command_line_entropy']['mean']) /
            self.baseline_stats['command_line_entropy']['std']
        )

        # ═══════════ User Features (3) ═══════════
        result['is_system_user'] = result['User'].apply(
            lambda x: 1 if 'NT AUTHORITY' in str(x).upper() or
            'SYSTEM' in str(x).upper() else 0)
        result['user_encoded'] = self._label_encode(
            result['User'].str.lower(), 'user')
        result['integrity_encoded'] = result['IntegrityLevel'].map({
            'Low': 0, 'Medium': 1, 'High': 2, 'System': 3,
        }).fillna(1).astype(int)

        # Clean up temporary columns
        result.drop(columns=['_child_basename', '_parent_basename',
                             '_cmdline_lower'], inplace=True)

        return result

    def _check_suspicious_flags(self, cmdline_lower: str) -> bool:
        """Check if command line contains any suspicious flags."""
        return any(flag in cmdline_lower for flag in self.SUSPICIOUS_FLAGS)

    def _calc_suspicious_ratio(self, row) -> float:
        """Calculate the ratio of suspicious arguments to total arguments."""
        cmdline = str(row.get('CommandLine', '')).lower()
        args = cmdline.split()
        if not args:
            return 0.0
        suspicious_count = sum(
            1 for arg in args
            if any(flag in arg for flag in self.SUSPICIOUS_FLAGS)
        )
        return round(suspicious_count / len(args), 4)

    def _estimate_depth(self, parent_basename: str) -> int:
        """
        Estimate process ancestry depth from the parent process.
        Root processes (explorer.exe, services.exe) = depth 1 for their children.
        Script engines as parents = depth 2+ (assumed chain).
        """
        if parent_basename in self.ROOT_PROCESSES:
            return 1
        elif parent_basename in self.SCRIPTING_ENGINES:
            return 2  # Script engine is usually spawned by something else
        elif parent_basename in self.OFFICE_APPS:
            return 2  # Office apps are spawned by explorer
        elif parent_basename in self.BROWSERS:
            return 2
        else:
            return 3  # Unknown parent — likely deeper in chain

    def _calc_pair_rarity(self, row) -> float:
        """
        Calculate how rare a parent→child process pair is relative to baseline.
        Uses negative log probability: higher = rarer.
        Unseen pairs get max_rarity + 1.
        """
        parent = self._get_basename(str(row.get('ParentImage', '')))
        child = self._get_basename(str(row.get('Image', '')))
        pair_key = f"{parent}>{child}"

        if not self.pair_frequencies:
            return 0.0  # No baseline available

        if pair_key in self.pair_frequencies:
            freq = self.pair_frequencies[pair_key]
            # Negative log10 probability: common pairs → low score, rare → high
            return round(-math.log10(max(freq, 1e-10)), 4)
        else:
            # Pair never seen in baseline — very suspicious
            if self.pair_frequencies:
                max_rarity = max(
                    -math.log10(max(f, 1e-10))
                    for f in self.pair_frequencies.values()
                )
                return round(max_rarity + 1.0, 4)
            return 5.0  # Default high rarity

    def _label_encode(self, series: pd.Series, name: str) -> pd.Series:
        """Label encode a categorical series, handling unseen values."""
        if name not in self.label_encoders:
            self.label_encoders[name] = {}

        encoded = []
        mapping = self.label_encoders[name]
        for val in series:
            val_str = str(val)
            if val_str not in mapping:
                mapping[val_str] = len(mapping)
            encoded.append(mapping[val_str])

        return pd.Series(encoded, index=series.index)

    def get_feature_columns(self) -> list:
        """Return list of all numeric feature column names for ML input."""
        return [
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

    def save_baseline_stats(self, path: str):
        """Save baseline statistics to JSON for reproducibility."""
        stats = {
            'baseline_stats': self.baseline_stats,
            'pair_frequencies': self.pair_frequencies,
            'total_baseline_events': self.total_baseline_events,
            'label_encoders': self.label_encoders,
        }
        with open(path, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"  ✓ Saved baseline stats to: {os.path.basename(path)}")

    def load_baseline_stats(self, path: str):
        """Load previously saved baseline statistics."""
        with open(path, 'r') as f:
            stats = json.load(f)
        self.baseline_stats = stats['baseline_stats']
        self.pair_frequencies = stats['pair_frequencies']
        self.total_baseline_events = stats['total_baseline_events']
        self.label_encoders = stats.get('label_encoders', {})


# ─────────────────────── Main ─────────────────────────────────

def main():
    """Run feature engineering on the full dataset."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(project_root, "data")

    benign_path = os.path.join(data_dir, "benign_baseline.csv")
    full_path = os.path.join(data_dir, "full_dataset.csv")

    if not os.path.exists(full_path):
        print("[!] Dataset not found. Run generate_synthetic_data.py first.")
        sys.exit(1)

    print("=" * 70)
    print("  LOLBins Detection Engine — Feature Engineering")
    print("=" * 70)

    # Step 1: Build baseline from benign data
    print("\n[1/4] Building benign baseline statistics...")
    fe = FeatureEngineer(benign_baseline_path=benign_path)

    # Step 2: Load full dataset
    print("\n[2/4] Loading full dataset...")
    df = pd.read_csv(full_path)
    print(f"    ✓ Loaded {len(df)} events")

    # Step 3: Extract features
    print("\n[3/4] Extracting 29 features...")
    df_features = fe.extract_features(df)

    feature_cols = fe.get_feature_columns()
    print(f"    ✓ Extracted {len(feature_cols)} numeric features")

    # Step 4: Save outputs
    print("\n[4/4] Saving outputs...")
    output_path = os.path.join(data_dir, "feature_matrix.csv")
    df_features.to_csv(output_path, index=False)
    print(f"    ✓ Feature matrix: {output_path}")

    stats_path = os.path.join(data_dir, "benign_baseline_stats.json")
    fe.save_baseline_stats(stats_path)

    # Print summary statistics
    print("\n" + "=" * 70)
    print("  FEATURE SUMMARY STATISTICS")
    print("=" * 70)

    for col in feature_cols:
        if col in df_features.columns:
            vals = df_features[col]
            print(f"\n  {col}:")
            print(f"    mean={vals.mean():.3f}, std={vals.std():.3f}, "
                  f"min={vals.min():.3f}, max={vals.max():.3f}")

            # Show benign vs malicious split if labels available
            if 'is_malicious' in df_features.columns:
                benign_vals = df_features[
                    df_features['is_malicious'] == 0][col]
                mal_vals = df_features[
                    df_features['is_malicious'] == 1][col]
                if len(mal_vals) > 0:
                    print(f"    benign_mean={benign_vals.mean():.3f}, "
                          f"malicious_mean={mal_vals.mean():.3f}, "
                          f"separation={abs(mal_vals.mean() - benign_vals.mean()):.3f}")

    print("\n" + "=" * 70)
    print("  Feature engineering complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
