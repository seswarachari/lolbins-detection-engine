#!/usr/bin/env python3
"""
Simplified Sigma Rule Engine for LOLBin Detection
===================================================
Loads YAML-based Sigma detection rules and evaluates process creation events
against them using field matching with Sigma modifiers.

NOTE: In production, use pySigma (https://github.com/SigmaHQ/pySigma) or a
real SIEM's Sigma backend (Splunk, Elasticsearch, Microsoft Sentinel). This
simplified engine demonstrates the detection concept for portfolio/interview
purposes and handles the subset of Sigma syntax used by our detection rules.

Supported Sigma modifiers: |contains, |startswith, |endswith, |re
Supported conditions: selection, selection1 or selection2, selection and not filter

Author: Eswar Achari
"""

import os
import sys
import re
from typing import Dict, List, Optional, Any

import yaml
import pandas as pd


class SigmaEngine:
    """
    A simplified Sigma rule matching engine that loads YAML detection rules
    and evaluates process creation events against them.
    
    Design Decision: We implement a subset of the full Sigma specification
    sufficient for LOLBin detection rules. This trades full Sigma compatibility
    for simplicity and transparency — in interviews, being able to explain
    exactly how each rule matches is more valuable than using a black-box library.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize the Sigma engine and load rules.
        
        Args:
            rules_dir: Path to directory containing .yml/.yaml rule files.
                       Defaults to rules/sigma_rules/ relative to project root.
        """
        if rules_dir is None:
            project_root = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))
            rules_dir = os.path.join(project_root, 'rules', 'sigma_rules')

        self.rules = []
        self.rules_dir = rules_dir
        self.load_rules(rules_dir)

    def load_rules(self, rules_dir: str):
        """
        Load all YAML Sigma rule files from the specified directory.
        
        Each rule is parsed into a structured dict containing:
        - title, id, level, tags (metadata)
        - detection (parsed selection criteria + condition)
        """
        self.rules = []

        if not os.path.exists(rules_dir):
            print(f"  [!] Rules directory not found: {rules_dir}")
            return

        rule_files = [
            f for f in os.listdir(rules_dir)
            if f.endswith(('.yml', '.yaml'))
        ]

        for filename in sorted(rule_files):
            filepath = os.path.join(rules_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    rule_data = yaml.safe_load(f)

                if rule_data and 'detection' in rule_data:
                    parsed_rule = self._parse_rule(rule_data, filename)
                    if parsed_rule:
                        self.rules.append(parsed_rule)

            except Exception as e:
                print(f"  [!] Error loading rule {filename}: {e}")

        print(f"  [*] Loaded {len(self.rules)} Sigma rules from {rules_dir}")

    def _parse_rule(self, rule_data: Dict, filename: str) -> Optional[Dict]:
        """Parse a raw YAML rule into a structured detection rule."""
        try:
            detection = rule_data.get('detection', {})
            condition = detection.get('condition', 'selection')

            # Parse all selection blocks (selection, selection_*, filter*)
            selections = {}
            filters = {}
            for key, value in detection.items():
                if key == 'condition':
                    continue
                if key.startswith('filter'):
                    filters[key] = self._parse_selection(value)
                else:
                    selections[key] = self._parse_selection(value)

            return {
                'title': rule_data.get('title', filename),
                'id': rule_data.get('id', ''),
                'level': rule_data.get('level', 'medium'),
                'tags': rule_data.get('tags', []),
                'description': rule_data.get('description', ''),
                'falsepositives': rule_data.get('falsepositives', []),
                'selections': selections,
                'filters': filters,
                'condition': condition,
                'filename': filename,
            }
        except Exception as e:
            print(f"  [!] Error parsing rule {filename}: {e}")
            return None

    def _parse_selection(self, selection: Dict) -> List[Dict]:
        """
        Parse a Sigma selection block into a list of field matchers.
        
        Each field matcher contains:
        - field: the event field name (e.g., 'Image', 'CommandLine')
        - modifier: the matching modifier (contains, startswith, endswith, re)
        - values: list of patterns to match against
        """
        matchers = []

        if not isinstance(selection, dict):
            return matchers

        for field_key, values in selection.items():
            # Parse field name and modifier from key like 'CommandLine|contains'
            parts = field_key.split('|')
            field_name = parts[0]
            modifier = parts[1] if len(parts) > 1 else 'exact'

            # Normalize values to a list
            if isinstance(values, str):
                values = [values]
            elif not isinstance(values, list):
                values = [str(values)]

            matchers.append({
                'field': field_name,
                'modifier': modifier,
                'values': values,
            })

        return matchers

    def _match_field(self, event_value: str, modifier: str,
                     patterns: List[str]) -> bool:
        """
        Check if an event field value matches any of the patterns using
        the specified Sigma modifier.
        
        Sigma matching logic:
        - |contains: pattern is a substring of the value
        - |startswith: value starts with pattern
        - |endswith: value ends with pattern
        - |re: pattern is a regex
        - exact: exact string match (case-insensitive)
        
        Within a single field's values list, matching is OR (any match = True).
        """
        if not event_value:
            return False

        event_lower = str(event_value).lower()

        for pattern in patterns:
            pattern_lower = str(pattern).lower()

            try:
                if modifier == 'contains':
                    if pattern_lower in event_lower:
                        return True
                elif modifier == 'startswith':
                    if event_lower.startswith(pattern_lower):
                        return True
                elif modifier == 'endswith':
                    if event_lower.endswith(pattern_lower):
                        return True
                elif modifier == 're':
                    if re.search(pattern, str(event_value), re.IGNORECASE):
                        return True
                elif modifier == 'exact':
                    if event_lower == pattern_lower:
                        return True
                else:
                    # Unknown modifier — fall back to contains
                    if pattern_lower in event_lower:
                        return True
            except re.error:
                # Invalid regex pattern — skip
                continue

        return False

    def _evaluate_selection(self, event: Dict, matchers: List[Dict]) -> bool:
        """
        Evaluate a single selection block against an event.
        All field matchers in a selection must match (AND logic).
        Within each field's values, any match suffices (OR logic).
        """
        for matcher in matchers:
            field = matcher['field']
            modifier = matcher['modifier']
            values = matcher['values']

            # Get the event field value
            event_value = event.get(field, '')

            if not self._match_field(event_value, modifier, values):
                return False  # AND logic: one miss = selection doesn't match

        return True  # All field matchers matched

    def evaluate_event(self, event: Dict) -> List[Dict]:
        """
        Evaluate a single event against all loaded Sigma rules.
        
        Args:
            event: Dict with Sysmon event fields (Image, CommandLine, etc.)
            
        Returns:
            List of matched rule info dicts, each containing:
            - rule_title, rule_id, level, mitre_tags, description
        """
        matches = []

        for rule in self.rules:
            if self._evaluate_condition(event, rule):
                # Extract MITRE tags (tags starting with 'attack.t')
                mitre_tags = [
                    t for t in rule.get('tags', [])
                    if t.startswith('attack.t')
                ]
                matches.append({
                    'rule_title': rule['title'],
                    'rule_id': rule['id'],
                    'level': rule['level'],
                    'mitre_tags': mitre_tags,
                    'description': rule.get('description', ''),
                })

        return matches

    def _evaluate_condition(self, event: Dict, rule: Dict) -> bool:
        """
        Evaluate the rule's condition string against the event.
        
        Supported conditions:
        - 'selection' (simple single selection)
        - 'selection_x or selection_y' (OR of named selections)
        - 'selection and not filter' (selection with exclusion)
        """
        condition = rule.get('condition', 'selection')
        selections = rule.get('selections', {})
        filters = rule.get('filters', {})

        # Handle 'and not filter' conditions
        has_filter = False
        filter_pass = False
        if 'and not' in condition:
            has_filter = True
            # Check if any filter matches
            for filter_name, filter_matchers in filters.items():
                if self._evaluate_selection(event, filter_matchers):
                    filter_pass = True
                    break

        # Handle OR conditions: "selection_x or selection_y"
        if ' or ' in condition:
            # Parse selection names from condition
            parts = condition.replace(' and not ', ' ANDNOT ').split(' or ')
            any_match = False
            for part in parts:
                part = part.strip().split(' ANDNOT ')[0].strip()
                if part in selections:
                    if self._evaluate_selection(event, selections[part]):
                        any_match = True
                        break
            result = any_match
        else:
            # Simple condition — check the named selection
            sel_name = condition.split(' and not ')[0].strip()
            if sel_name in selections:
                result = self._evaluate_selection(event, selections[sel_name])
            elif 'selection' in selections:
                result = self._evaluate_selection(event, selections['selection'])
            else:
                # Try first selection
                if selections:
                    first_sel = list(selections.values())[0]
                    result = self._evaluate_selection(event, first_sel)
                else:
                    result = False

        # Apply filter exclusion
        if has_filter and filter_pass:
            result = False

        return result

    def evaluate_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Evaluate all events in a DataFrame against all loaded Sigma rules.
        
        Adds these columns:
        - sigma_match: boolean, whether any rule matched
        - sigma_rule_name: name of matched rule (or 'None')
        - sigma_level: severity level of matched rule (or 'none')
        - sigma_mitre_tags: MITRE ATT&CK tags from matched rule
        """
        results = {
            'sigma_match': [],
            'sigma_rule_name': [],
            'sigma_level': [],
            'sigma_mitre_tags': [],
        }

        for _, row in df.iterrows():
            event = row.to_dict()
            matches = self.evaluate_event(event)

            if matches:
                # Use highest-severity match
                severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
                matches.sort(
                    key=lambda m: severity_order.get(m['level'], 0),
                    reverse=True
                )
                best_match = matches[0]
                results['sigma_match'].append(True)
                results['sigma_rule_name'].append(best_match['rule_title'])
                results['sigma_level'].append(best_match['level'])
                results['sigma_mitre_tags'].append(
                    ', '.join(best_match['mitre_tags']))
            else:
                results['sigma_match'].append(False)
                results['sigma_rule_name'].append('None')
                results['sigma_level'].append('none')
                results['sigma_mitre_tags'].append('')

        result_df = df.copy()
        for col, values in results.items():
            result_df[col] = values

        return result_df

    def get_rules_summary(self) -> pd.DataFrame:
        """Return a summary DataFrame of all loaded rules."""
        rows = []
        for rule in self.rules:
            mitre = [t for t in rule.get('tags', []) if t.startswith('attack.t')]
            rows.append({
                'title': rule['title'],
                'level': rule['level'],
                'mitre_tags': ', '.join(mitre),
                'filename': rule['filename'],
            })
        return pd.DataFrame(rows)


# ─────────────────────── Main ─────────────────────────────────

def main():
    """Run Sigma engine evaluation on the full dataset."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(project_root, "data")
    full_path = os.path.join(data_dir, "full_dataset.csv")

    if not os.path.exists(full_path):
        print("[!] Dataset not found. Run generate_synthetic_data.py first.")
        sys.exit(1)

    print("=" * 70)
    print("  LOLBins Detection Engine — Sigma Rule Engine")
    print("=" * 70)

    # Load rules
    print("\n[1/3] Loading Sigma rules...")
    engine = SigmaEngine()

    # Print rules summary
    summary = engine.get_rules_summary()
    print("\n  Loaded Rules:")
    for _, rule in summary.iterrows():
        print(f"    [{rule['level']:8s}] {rule['title']}")
        print(f"             MITRE: {rule['mitre_tags']}")

    # Load and evaluate dataset
    print("\n[2/3] Loading dataset...")
    df = pd.read_csv(full_path)
    print(f"    ✓ Loaded {len(df)} events")

    print("\n[3/3] Evaluating events against Sigma rules...")
    result_df = engine.evaluate_dataset(df)

    # Statistics
    total_matches = result_df['sigma_match'].sum()
    print(f"\n    ✓ Total Sigma matches: {total_matches}/{len(df)} events")

    # Break down by label
    if 'is_malicious' in result_df.columns:
        print("\n  Detection Breakdown:")
        for label in ['benign', 'malicious', 'gray_area']:
            subset = result_df[result_df['label'] == label]
            matches = subset['sigma_match'].sum()
            print(f"    {label:12s}: {matches}/{len(subset)} matched "
                  f"({matches/max(len(subset),1)*100:.1f}%)")

    # Show matched rule distribution
    matched = result_df[result_df['sigma_match']]
    if len(matched) > 0:
        print("\n  Matched Rules Distribution:")
        for rule_name, count in matched['sigma_rule_name'].value_counts().items():
            print(f"    {rule_name}: {count} events")

    # Save results
    output_path = os.path.join(data_dir, "sigma_results.csv")
    result_df.to_csv(output_path, index=False)
    print(f"\n  ✓ Results saved to: {output_path}")

    print("\n" + "=" * 70)
    print("  Sigma engine evaluation complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
