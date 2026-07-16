#!/usr/bin/env python3
"""
Behavioral Chain Analyzer for LOLBins Detection Engine
=======================================================
Analyzes process parent-child relationships to detect known malicious
execution chains and suspicious process ancestry patterns.

This layer complements Sigma rules and ML scoring by understanding the
CONTEXT of process execution — a cmd.exe running certutil.exe is more
suspicious when cmd.exe was spawned by winword.exe (macro attack chain)
than by explorer.exe (user typing a command).

Author: Eswar Achari
"""

import os
import sys
import re
from typing import Dict, Optional, Tuple

import pandas as pd


class ChainAnalyzer:
    """
    Analyzes process creation events for known malicious parent-child
    execution chains and assigns risk scores based on pattern matching
    and contextual modifiers.
    """

    # Known malicious parent→child chain patterns with base risk scores
    # Each key is (parent_basename, child_basename), value has score and description
    MALICIOUS_CHAINS = {
        # Office macro attack chains — very high confidence
        ('winword.exe', 'cmd.exe'): {
            'score': 80, 'desc': 'Office Word spawning command shell (macro indicator)'},
        ('winword.exe', 'powershell.exe'): {
            'score': 85, 'desc': 'Office Word directly spawning PowerShell'},
        ('winword.exe', 'mshta.exe'): {
            'score': 85, 'desc': 'Office Word spawning HTA handler'},
        ('winword.exe', 'wscript.exe'): {
            'score': 80, 'desc': 'Office Word spawning Windows Script Host'},
        ('winword.exe', 'cscript.exe'): {
            'score': 80, 'desc': 'Office Word spawning CScript'},
        ('excel.exe', 'cmd.exe'): {
            'score': 80, 'desc': 'Excel spawning command shell (macro indicator)'},
        ('excel.exe', 'powershell.exe'): {
            'score': 85, 'desc': 'Excel directly spawning PowerShell'},
        ('powerpnt.exe', 'cmd.exe'): {
            'score': 80, 'desc': 'PowerPoint spawning command shell'},
        ('outlook.exe', 'powershell.exe'): {
            'score': 80, 'desc': 'Outlook spawning PowerShell'},
        ('outlook.exe', 'cmd.exe'): {
            'score': 75, 'desc': 'Outlook spawning command shell'},

        # LOLBin abuse chains — medium-high confidence
        ('cmd.exe', 'certutil.exe'): {
            'score': 50, 'desc': 'Command shell invoking certutil'},
        ('powershell.exe', 'certutil.exe'): {
            'score': 65, 'desc': 'PowerShell invoking certutil'},
        ('cmd.exe', 'regsvr32.exe'): {
            'score': 55, 'desc': 'Command shell invoking regsvr32'},
        ('cmd.exe', 'rundll32.exe'): {
            'score': 50, 'desc': 'Command shell invoking rundll32'},
        ('cmd.exe', 'bitsadmin.exe'): {
            'score': 55, 'desc': 'Command shell invoking bitsadmin'},
        ('powershell.exe', 'bitsadmin.exe'): {
            'score': 60, 'desc': 'PowerShell invoking bitsadmin'},
        ('cmd.exe', 'mshta.exe'): {
            'score': 60, 'desc': 'Command shell invoking mshta'},
        ('powershell.exe', 'msbuild.exe'): {
            'score': 70, 'desc': 'PowerShell spawning MSBuild'},
        ('cmd.exe', 'msbuild.exe'): {
            'score': 65, 'desc': 'Command shell spawning MSBuild'},
        ('cmd.exe', 'wscript.exe'): {
            'score': 55, 'desc': 'Command shell invoking WScript'},
        ('cmd.exe', 'cscript.exe'): {
            'score': 55, 'desc': 'Command shell invoking CScript'},

        # Service exploitation chains — medium confidence
        ('svchost.exe', 'cmd.exe'): {
            'score': 45, 'desc': 'Service host spawning command shell'},
        ('svchost.exe', 'powershell.exe'): {
            'score': 55, 'desc': 'Service host spawning PowerShell'},

        # Browser exploitation chains
        ('chrome.exe', 'cmd.exe'): {
            'score': 70, 'desc': 'Browser spawning command shell (possible exploit)'},
        ('chrome.exe', 'powershell.exe'): {
            'score': 75, 'desc': 'Browser spawning PowerShell (possible exploit)'},
        ('firefox.exe', 'cmd.exe'): {
            'score': 70, 'desc': 'Browser spawning command shell'},
        ('iexplore.exe', 'cmd.exe'): {
            'score': 70, 'desc': 'IE spawning command shell'},
        ('msedge.exe', 'cmd.exe'): {
            'score': 70, 'desc': 'Edge spawning command shell'},

        # Explorer spawning LOLBins — lower base but modifiable
        ('explorer.exe', 'mshta.exe'): {
            'score': 40, 'desc': 'Explorer launching HTA handler'},
        ('explorer.exe', 'regsvr32.exe'): {
            'score': 35, 'desc': 'Explorer launching regsvr32'},
        ('explorer.exe', 'rundll32.exe'): {
            'score': 25, 'desc': 'Explorer launching rundll32'},
    }

    # Office application basenames
    OFFICE_APPS = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'}

    # Known LOLBin basenames
    LOLBINS = {
        'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
        'cscript.exe', 'wscript.exe', 'bitsadmin.exe', 'msbuild.exe',
        'installutil.exe',
    }

    # Script engines
    SCRIPT_ENGINES = {'powershell.exe', 'cmd.exe', 'cscript.exe',
                      'wscript.exe', 'mshta.exe'}

    def __init__(self):
        """Initialize the chain analyzer."""
        pass

    @staticmethod
    def _get_basename(image_path: str) -> str:
        """Extract lowercase basename from a Windows image path."""
        if not image_path or pd.isna(image_path):
            return 'unknown'
        return image_path.replace('/', '\\').split('\\')[-1].lower()

    def analyze_event(self, event: Dict) -> Dict:
        """
        Analyze a single process creation event for suspicious chain patterns.
        
        Args:
            event: Dict with Sysmon event fields.
            
        Returns:
            Dict with:
            - chain_risk_score: 0-100 risk score
            - chain_description: Human-readable description
            - chain_matched_pattern: Boolean
        """
        parent = self._get_basename(str(event.get('ParentImage', '')))
        child = self._get_basename(str(event.get('Image', '')))
        cmdline = str(event.get('CommandLine', '')).lower()
        timestamp = str(event.get('UtcTime', ''))

        # Check for known malicious chain pattern
        chain_key = (parent, child)
        base_score = 0
        description = f"{parent} → {child}: No known suspicious pattern"
        matched = False

        if chain_key in self.MALICIOUS_CHAINS:
            chain_info = self.MALICIOUS_CHAINS[chain_key]
            base_score = chain_info['score']
            description = f"{parent} → {child}: {chain_info['desc']}"
            matched = True

        # ═══════════ Apply Risk Modifiers ═══════════

        modifiers = []

        # +20 if parent is an Office app AND child is a script engine
        if parent in self.OFFICE_APPS and child in self.SCRIPT_ENGINES:
            base_score += 20
            modifiers.append("+20 Office→Script chain")

        # +15 if command line contains a URL (network activity)
        if re.search(r'https?://', cmdline):
            base_score += 15
            modifiers.append("+15 URL in command")

        # +10 if child is a known LOLBin
        if child in self.LOLBINS and not matched:
            base_score += 10
            modifiers.append("+10 LOLBin child")

        # +10 if off-hours execution (0-5am)
        try:
            hour = pd.to_datetime(timestamp).hour
            if 0 <= hour <= 5:
                base_score += 10
                modifiers.append("+10 off-hours")
        except (ValueError, TypeError):
            pass

        # +10 if encoded command detected
        if '-enc ' in cmdline or '-encodedcommand' in cmdline:
            base_score += 10
            modifiers.append("+10 encoded command")

        # +5 if suspicious flags present
        suspicious_flags = ['-nop', '-w hidden', 'javascript:', '/i:http',
                           '-urlcache', '/transfer', '//e:jscript']
        if any(flag in cmdline for flag in suspicious_flags):
            base_score += 5
            modifiers.append("+5 suspicious flags")

        # Cap at 100
        final_score = min(base_score, 100)

        # Enhance description with modifiers
        if modifiers:
            description += f" [Modifiers: {', '.join(modifiers)}]"

        return {
            'chain_risk_score': final_score,
            'chain_description': description,
            'chain_matched_pattern': matched,
        }

    def analyze_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Analyze all events in a DataFrame for chain patterns.
        
        Adds columns: chain_risk_score, chain_description, chain_matched_pattern
        """
        results = []
        for _, row in df.iterrows():
            result = self.analyze_event(row.to_dict())
            results.append(result)

        result_df = pd.DataFrame(results)
        output = df.copy()
        output['chain_risk_score'] = result_df['chain_risk_score'].values
        output['chain_description'] = result_df['chain_description'].values
        output['chain_matched_pattern'] = result_df['chain_matched_pattern'].values

        return output


# ─────────────────────── Main ─────────────────────────────────

def main():
    """Run chain analysis on the full dataset."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(project_root, "data")
    full_path = os.path.join(data_dir, "full_dataset.csv")

    if not os.path.exists(full_path):
        print("[!] Dataset not found. Run generate_synthetic_data.py first.")
        sys.exit(1)

    print("=" * 70)
    print("  LOLBins Detection Engine — Chain Analyzer")
    print("=" * 70)

    # Load dataset
    print("\n[1/2] Loading dataset...")
    df = pd.read_csv(full_path)
    print(f"    ✓ Loaded {len(df)} events")

    # Analyze chains
    print("\n[2/2] Analyzing process chains...")
    analyzer = ChainAnalyzer()
    result_df = analyzer.analyze_dataset(df)

    # Statistics
    print("\n" + "=" * 70)
    print("  CHAIN ANALYSIS RESULTS")
    print("=" * 70)

    for label_name in ['benign', 'malicious', 'gray_area']:
        subset = result_df[result_df['label'] == label_name]
        if len(subset) > 0:
            scores = subset['chain_risk_score']
            matched = subset['chain_matched_pattern'].sum()
            print(f"\n  {label_name.upper()} ({len(subset)} events):")
            print(f"    Mean chain risk: {scores.mean():.1f}")
            print(f"    Max chain risk:  {scores.max():.0f}")
            print(f"    Patterns matched: {matched} ({matched/len(subset)*100:.1f}%)")
            high_risk = (scores > 50).sum()
            print(f"    High risk (>50):  {high_risk} ({high_risk/len(subset)*100:.1f}%)")

    # Show top suspicious chains
    print("\n  TOP 15 HIGHEST CHAIN RISK SCORES:")
    print("  " + "-" * 68)
    top = result_df.nlargest(15, 'chain_risk_score')
    for _, row in top.iterrows():
        label = row.get('label', '?')
        score = row['chain_risk_score']
        desc = row['chain_description'][:80]
        print(f"  [{label:10s}] Score: {score:3.0f} | {desc}")

    # Save results
    output_path = os.path.join(data_dir, "chain_analysis.csv")
    result_df.to_csv(output_path, index=False)
    print(f"\n  ✓ Results saved to: {output_path}")

    print("\n" + "=" * 70)
    print("  Chain analysis complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
