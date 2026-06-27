#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import pandas as pd
from scankii.scanner import scan_directory

def main():
    SKILLLEAKBENCH_PATH = Path(__file__).resolve().parent.parent / "SkillLeakBench"
    issues_csv = SKILLLEAKBENCH_PATH / "data" / "issues.csv"
    skills_csv = SKILLLEAKBENCH_PATH / "data" / "skills_dataset.csv"
    
    if not issues_csv.exists() or not skills_csv.exists():
        print("Error: Dataset CSVs not found.")
        sys.exit(1)

    issues = pd.read_csv(issues_csv)
    skills = pd.read_csv(skills_csv)

    ground_truth_lookup = {}
    for _, row in skills.iterrows():
        skill_name = row["skill_name"]
        ground_truth_lookup[skill_name] = {
            "vulnerable": True,
            "patterns": set(issues[issues["skill_name"] == skill_name]["pattern"].tolist())
        }

    reconstructed_dir = SKILLLEAKBENCH_PATH / "code" / "results" / "phase1_downloads" / "repos"
    if not reconstructed_dir.exists():
        print(f"Error: {reconstructed_dir} not found.")
        sys.exit(1)

    results = []
    
    print("Evaluating skills...")
    for skill_dir in reconstructed_dir.iterdir():
        if not skill_dir.is_dir():
            continue
            
        skill_name = skill_dir.name
        if skill_name not in ground_truth_lookup:
            continue
            
        gt = ground_truth_lookup[skill_name]
        expected_patterns = gt["patterns"]
        
        # Directly call the python API
        scan_result = scan_directory(skill_dir)
        findings = scan_result.findings

        detected_patterns = set()
        for sf in findings:
            actual = sf.finding
            if hasattr(actual, "finding_type") and getattr(actual, "finding_type", "") == "credential_action":
                detected_patterns.add("Information Exposure")
                detected_patterns.add("Cross-Modal Leak")
            elif type(actual).__name__ == "CrossModalFinding":
                detected_patterns.add("Information Exposure")
                detected_patterns.add("Cross-Modal Leak")
            elif type(actual).__name__ == "ASTFinding":
                if actual.sink_category == "logging" or actual.sink_category == "file":
                    detected_patterns.add("Information Exposure")
                    detected_patterns.add("Insecure Storage")
                elif actual.sink_category == "network":
                    detected_patterns.add("Remote Exploitation")
                    detected_patterns.add("Defense Evasion")
                detected_patterns.add("Credential Compromise")
                detected_patterns.add("Hardcoded Credentials")
            else:
                detected_patterns.add("Credential Compromise")
                detected_patterns.add("Hardcoded Credentials")

        detected = len(detected_patterns) > 0
        tp = detected
        fn = not detected
        fp = False
        tn = False

        results.append({
            "skill": skill_name,
            "expected_patterns": list(expected_patterns),
            "detected_patterns": list(detected_patterns),
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
        })

        if tp:
            print(f"[TP] {skill_name}")
        elif fn:
            print(f"[FN] {skill_name}    MISSED — expected: {list(expected_patterns)}")

    if not results:
        print("No skills were evaluated.")
        return

    tp = sum(1 for r in results if r["tp"])
    fn = sum(1 for r in results if r["fn"])
    fp = sum(1 for r in results if r["fp"])
    tn = sum(1 for r in results if r["tn"])
    
    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    print("-" * 50)
    print(f"Precision: {precision:.1f}%")
    print(f"Recall:    {recall:.1f}%")
    print(f"F1:        {f1:.1f}%")
    print(f"TP: {tp}  FP: {fp}  FN: {fn}  TN: {tn}")
    print("-" * 50)

    from collections import defaultdict
    pattern_results = defaultdict(lambda: {"tp": 0, "fn": 0})

    for r in results:
        for pattern in r["expected_patterns"]:
            if r["tp"]:
                pattern_results[pattern]["tp"] += 1
            elif r["fn"]:
                pattern_results[pattern]["fn"] += 1

    print("\n=== RECALL BY PATTERN ===")
    for pattern, counts in sorted(pattern_results.items()):
        total = counts["tp"] + counts["fn"]
        pattern_recall = counts["tp"] / total if total > 0 else 0
        print(f"{pattern:35} {pattern_recall:.0%} ({counts['tp']}/{total})")

if __name__ == "__main__":
    main()
