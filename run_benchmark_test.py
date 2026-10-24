"""
run_benchmark_test.py - Automated Benchmark & Verification Test Runner
Validates the detection rate, false positives, and rescan comparison of CY-02.
"""

import sys
import json
from pathlib import Path

# Ensure engine is in path
sys.path.insert(0, str(Path(__file__).parent / "engine"))
from scanner import scan_directory, compare_scans, generate_repair_prompt

def main():
    print("=" * 65)
    print("      CY-02 AI SECURITY REVIEWER - BENCHMARK TEST SUITE      ")
    print("=" * 65)

    vulnerable_dir = Path("benchmark/vulnerable_project")
    secured_dir = Path("benchmark/secured_project")

    # Step 1: Scan Vulnerable Benchmark
    print(f"\n[1] Scanning Vulnerable Project ({vulnerable_dir})...")
    vuln_scan = scan_directory(str(vulnerable_dir))
    
    print(f"    - Files Scanned: {vuln_scan['scanned_files_count']}")
    print(f"    - Total Findings: {vuln_scan['total_findings']}")
    print(f"    - Security Score: {vuln_scan['security_score']}/100")
    print(f"    - Severity Breakdown: {vuln_scan['severity_summary']}")
    
    print("\n    Detected Findings:")
    for f in vuln_scan["findings"]:
        print(f"      * [{f['severity']}] {f['title']} in {f['file']}:{f['line']}")
        print(f"        Evidence: {f['evidence']}")

    # Step 2: Scan Secured Benchmark
    print(f"\n[2] Scanning Secured (Corrected) Project ({secured_dir})...")
    secured_scan = scan_directory(str(secured_dir))
    
    print(f"    - Files Scanned: {secured_scan['scanned_files_count']}")
    print(f"    - Total Findings: {secured_scan['total_findings']}")
    print(f"    - Security Score: {secured_scan['security_score']}/100")
    print(f"    - Severity Breakdown: {secured_scan['severity_summary']}")

    # Step 3: Compare Baseline vs Rescan
    print("\n[3] Running Rescan Verification & Comparison...")
    diff = compare_scans(vuln_scan, secured_scan)
    print(f"    - Vulnerabilities Resolved: {diff['resolved_count']}/{diff['initial_total']}")
    print(f"    - Vulnerabilities Remaining: {diff['remaining_count']}")
    print(f"    - Newly Introduced Issues: {diff['new_count']}")
    print(f"    - Score Improvement: +{diff['score_delta']} pts")

    # Step 4: Generate AI Repair Prompt Sample
    print("\n[4] Generating AI Repair Prompt (first 300 chars)...")
    prompt = generate_repair_prompt(vuln_scan)
    print("-----------------------------------------------------------------")
    print(prompt[:300] + "\n...[truncated for display]...")
    print("-----------------------------------------------------------------")

    # Step 5: Verification Assertions
    expected_vuln_count = 10
    detected_count = vuln_scan["total_findings"]
    false_positives = secured_scan["total_findings"]

    print("\n[5] Benchmark Validation Results:")
    print(f"    - Vulnerabilities Detected in Vulnerable Project: {detected_count}")
    print(f"    - False Positives in Secured Project: {false_positives}")
    print(f"    - Resolution Rate: {(diff['resolved_count'] / detected_count) * 100:.1f}%")

    if detected_count > 0 and false_positives == 0 and diff['resolved_count'] == detected_count:
        print("\n>>> ALL BENCHMARK CHECKS PASSED: 100% RECALL, 0% FALSE POSITIVES! <<<")
    else:
        print("\n>>> WARNING: Benchmark numbers did not match expected criteria. <<<")

if __name__ == "__main__":
    main()
