"""
build_real_dataset.py — Day-8 real-data collector for the FP classifier.

Reads datasets/day8/sources.json (provenance manifest). Two source kinds:

1. cve_pair: {repo, fix_commit, ghsa, cwe, advisory_url, file_keywords?}
   Clones the repo, checks out the fix commit's parent (vulnerable) and the
   fix commit itself, and runs the project's OWN scanner
   (backend/utils/securityScanner.js) on both checkouts.
     REAL (label=1): SAST finding on the VULNERABLE checkout whose
       (file, line) overlaps the fix diff AND whose CWE matches the
       advisory's CWE (guards against bundled unrelated changes landing
       in the same fix commit).
     FALSE_POSITIVE (label=0): SAST finding on the FIXED checkout whose
       (file, line) overlaps the fix diff — the scanner still flags code
       the patch made safe.
2. manual: {repo, commit, note}
   Scans the checkout and dumps every SAST finding with code context to
   review/<name>.jsonl for expert review. Labels are read back from
   labels/<name>.csv as finding_key -> {1,0,drop}. Only findings with an
   explicit 1/0 label land in the dataset; ambiguous ones are dropped.

Output: datasets/day8/real_findings.csv — RAW_FEATURES (same 18 the
service consumes) + label + provenance columns. NEVER any synthetic rows:
the script has no generator; every row traces to a real scan.

Feature enrichment mirrors backend/routes/scans.js: rule_id via the same
RULE_MAP, file_change_frequency via `git log` (capped at 50, 0 when the
checkout has no history), same_finding_seen_before_count /
developer_dismissed_similar_before = 0 (no production DB here — a fresh
finding has no history).

Usage:
  python3 build_real_dataset.py --scan            # (re)scan all sources -> review/*.jsonl
  python3 build_real_dataset.py --build           # assemble real_findings.csv from scans+labels
  python3 build_real_dataset.py --work-dir DIR    # where to clone (default ~/workspace/tmp-work/day8-datasets)
"""

import csv
import json
import os
import re
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# day8 -> datasets -> fp-classifier -> services -> backend
BACKEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..", ".."))
SCANNER_JS = os.path.join(BACKEND_DIR, "utils", "securityScanner.js")
REVIEW_DIR = os.path.join(BASE_DIR, "review")
LABELS_DIR = os.path.join(BASE_DIR, "labels")
OUT_CSV = os.path.join(BASE_DIR, "real_findings.csv")

# Must stay identical to the RULE_MAP in backend/routes/scans.js.
RULE_MAP = {
    "SAST-001": "sqli-concat",
    "SAST-002": "xss-unescaped",
    "SAST-003": "path-traversal",
    "SAST-004": "hardcoded-secret",
    "SAST-005": "insecure-deserialize",
    "SEC-001": "hardcoded-secret",
    "SEC-002": "hardcoded-secret",
    "SEC-003": "hardcoded-secret",
}

RAW_FEATURES = [
    "rule_id", "cwe_id",
    "is_string_concat", "is_parameterized_query",
    "has_sanitizer_nearby", "in_test_file", "is_in_vendor_or_generated_dir",
    "taint_source_distance", "function_complexity", "code_snippet_length",
    "variable_name_entropy", "is_user_input_direct", "has_type_validation",
    "is_third_party_lib_call", "same_finding_seen_before_count",
    "developer_dismissed_similar_before", "file_change_frequency",
    "is_authenticated_endpoint",
]
PROVENANCE_COLS = ["source_kind", "source_repo", "source_commit", "cve_ghsa", "label_note"]

NODE_BRIDGE = r"""
const { runSecurityScan } = require(process.argv[1]);
const r = runSecurityScan(process.argv[2]);
process.stdout.write(JSON.stringify(r.findings));
"""


def sh(args, cwd=None, timeout=600):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def ensure_clone(repo_url, work_dir, name):
    dest = os.path.join(work_dir, name)
    if not os.path.isdir(os.path.join(dest, ".git")):
        print(f"  cloning {repo_url} ...")
        r = sh(["git", "clone", "--quiet", repo_url, dest], timeout=900)
        if r.returncode != 0:
            raise RuntimeError(f"clone failed: {r.stderr[:300]}")
    return dest


def run_scanner(scan_root):
    r = sh(["node", "-e", NODE_BRIDGE, SCANNER_JS, scan_root], cwd=BACKEND_DIR, timeout=900)
    if r.returncode != 0:
        raise RuntimeError(f"scanner failed: {r.stderr[:500]}")
    return json.loads(r.stdout or "[]")


def file_change_frequency(repo_root, rel_path):
    try:
        r = sh(["git", "-C", repo_root, "log", "--format=%H", "--", rel_path], timeout=60)
        if r.returncode != 0:
            return 0
        return min(len([l for l in r.stdout.splitlines() if l.strip()]), 50)
    except Exception:
        return 0


def changed_lines(repo_root, old, new, side):
    """Line numbers changed on `side` ('old' or 'new') of old..new, per file."""
    per_file = {}
    r = sh(["git", "-C", repo_root, "diff", "-U0", "--name-only", old, new, "--",
            "*.js", "*.jsx", "*.ts", "*.tsx"], timeout=120)
    if r.returncode != 0:
        return per_file
    for f in r.stdout.splitlines():
        f = f.strip()
        if not f:
            continue
        d = sh(["git", "-C", repo_root, "diff", "-U0", old, new, "--", f], timeout=120)
        lines = set()
        pat = (r"^@@ -(\d+)(?:,(\d+))? " if side == "old"
               else r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? ")
        for m in re.finditer(pat, d.stdout, re.M):
            start = int(m.group(1))
            count = 1 if m.group(2) is None else int(m.group(2))
            lines.update(range(start, start + count))
        per_file[f] = lines
    return per_file


def enrich(finding, repo_root):
    """Attach production-shaped features (mirrors routes/scans.js enrichment)."""
    ml = finding.get("mlFeatures") or {}
    feats = {
        "rule_id": RULE_MAP.get(finding.get("ruleId"), finding.get("ruleId")),
        "cwe_id": finding.get("cweId"),        "is_string_concat": ml.get("is_string_concat", 0),
        "is_parameterized_query": ml.get("is_parameterized_query", 0),
        "has_sanitizer_nearby": ml.get("has_sanitizer_nearby", 0),
        "in_test_file": ml.get("in_test_file", 0),
        "is_in_vendor_or_generated_dir": ml.get("is_in_vendor_or_generated_dir", 0),
        "taint_source_distance": ml.get("taint_source_distance", 5),
        "function_complexity": ml.get("function_complexity", 1),
        "code_snippet_length": ml.get("code_snippet_length", 0),
        "variable_name_entropy": ml.get("variable_name_entropy", 0.0),
        "is_user_input_direct": ml.get("is_user_input_direct", 0),
        "has_type_validation": ml.get("has_type_validation", 0),
        "is_third_party_lib_call": ml.get("is_third_party_lib_call", 0),
        "same_finding_seen_before_count": 0,
        "developer_dismissed_similar_before": 0,
        "file_change_frequency": file_change_frequency(repo_root, finding.get("filePath", "")),
        "is_authenticated_endpoint": ml.get("is_authenticated_endpoint", 0),
    }
    # The AST extractor can emit null/NaN numerics on unparseable inputs
    # (e.g. minified vendor bundles: Math.min(5, undefined) -> NaN -> null
    # over the JSON bridge). Fall back to the documented defaults so a
    # poisoned feature never reaches the dataset.
    import math
    numeric_defaults = {
        "taint_source_distance": 5, "function_complexity": 1,
        "code_snippet_length": 0, "variable_name_entropy": 0.0,
        "file_change_frequency": 0, "same_finding_seen_before_count": 0,
    }
    for k, default in numeric_defaults.items():
        v = feats[k]
        if v is None or (isinstance(v, float) and math.isnan(v)):
            feats[k] = default
    return feats


def is_sast_finding(f):
    """Only SAST-rule findings belong in the FP-classifier dataset.

    IaC/API scanners also attach an `mlFeatures` object, but it is a
    different shape ({framework, category, ..., isIaC: true}) — not the 18
    SAST features the classifier consumes. Including them would poison the
    dataset with default-filled rows.
    """
    return bool(f.get("mlFeatures")) and str(f.get("ruleId", "")).startswith("SAST-")


def finding_key(f):
    return f"{f.get('ruleId')}|{f.get('filePath')}|{f.get('lineStart')}"


def file_context(repo_root, rel_path, line, n=12):
    p = os.path.join(repo_root, rel_path)
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return ""
    lo, hi = max(0, line - 1 - n), min(len(lines), line + n)
    return "\n".join(f"{i+1:6d}: {lines[i]}" for i in range(lo, hi))


def scan_cve_pair(src, work_dir):
    name = src["name"]
    repo_root = ensure_clone(src["repo"], work_dir, name)
    fix = src["fix_commit"]
    vuln = sh(["git", "-C", repo_root, "rev-parse", f"{fix}^"]).stdout.strip()
    rows = []
    for side, ref, label, note in (("old", vuln, 1, "scanner hit on CVE fix region (vuln commit)"),
                                   ("new", fix, 0, "scanner still flags fixed code")):
        sh(["git", "-C", repo_root, "checkout", "--quiet", ref])
        per_file = changed_lines(repo_root, vuln, fix, side)
        kws = [k.lower() for k in src.get("file_keywords", [])]
        findings = run_scanner(repo_root)
        for f in findings:
            if not is_sast_finding(f):
                continue
            fp = f.get("filePath", "")
            if kws and not any(k in fp.lower() for k in kws):
                continue
            if f.get("lineStart") not in per_file.get(fp, set()):
                continue
            if label == 1 and f.get("cweId") != src.get("cwe"):
                continue  # bundled unrelated change — not this CVE's truth
            feats = enrich(f, repo_root)
            feats.update({"source_kind": "cve_pair", "source_repo": src["repo"],
                          "source_commit": ref, "cve_ghsa": src.get("ghsa", ""),
                          "label_note": note, "label": label,
                          "_key": finding_key(f), "_snippet": f.get("codeSnippet", "")})
            rows.append(feats)
    print(f"  {name}: {len(rows)} labeled rows "
          f"({sum(r['label']==1 for r in rows)} REAL / {sum(r['label']==0 for r in rows)} FP)")
    return rows


def scan_manual(src, work_dir):
    name = src["name"]
    repo_root = ensure_clone(src["repo"], work_dir, name)
    sh(["git", "-C", repo_root, "checkout", "--quiet", src.get("commit", "HEAD")])
    commit = sh(["git", "-C", repo_root, "rev-parse", "HEAD"]).stdout.strip()
    findings = run_scanner(repo_root)
    os.makedirs(REVIEW_DIR, exist_ok=True)
    n = 0
    with open(os.path.join(REVIEW_DIR, f"{name}.jsonl"), "w", encoding="utf-8") as fh:
        for f in findings:
            if not is_sast_finding(f):
                continue
            feats = enrich(f, repo_root)
            rec = {"finding_key": finding_key(f), "rule_id": feats["rule_id"],
                   "cwe_id": feats["cwe_id"], "file": f.get("filePath"),
                   "line": f.get("lineStart"), "snippet": f.get("codeSnippet", ""),
                   "context": file_context(repo_root, f.get("filePath", ""), f.get("lineStart") or 0),
                   "features": feats,
                   "provenance": {"source_kind": "manual", "source_repo": src["repo"],
                                  "source_commit": commit, "cve_ghsa": "", "note": src.get("note", "")}}
            fh.write(json.dumps(rec) + "\n")
            n += 1
    print(f"  {name}: {n} findings dumped for review")
    return []


def build_rows(work_dir):
    manifest = json.load(open(os.path.join(BASE_DIR, "sources.json"), encoding="utf-8"))
    rows = []
    label_files = {}
    for src in manifest["sources"]:
        if src["kind"] == "cve_pair":
            rows.extend(scan_cve_pair(src, work_dir))
        elif src["kind"] == "manual":
            name = src["name"]
            lp = os.path.join(LABELS_DIR, f"{name}.csv")
            if not os.path.exists(lp):
                print(f"  {name}: no labels/{name}.csv yet — skipping (run --scan first, then label)")
                continue
            with open(lp, encoding="utf-8") as fh:
                label_files[name] = {r["finding_key"]: r["label"].strip() for r in csv.DictReader(fh)}
    # join manual labels with their review dumps
    manifest_by_name = {s["name"]: s for s in manifest["sources"] if s["kind"] == "manual"}
    for name, labels in label_files.items():
        rp = os.path.join(REVIEW_DIR, f"{name}.jsonl")
        kept = dropped = 0
        with open(rp, encoding="utf-8") as fh:
            for line in fh:
                rec = json.loads(line)
                lab = labels.get(rec["finding_key"], "drop").strip()
                if lab not in ("0", "1"):
                    dropped += 1
                    continue
                feats = rec["features"]
                feats.update({"source_kind": "manual", "source_repo": rec["provenance"]["source_repo"],
                              "source_commit": rec["provenance"]["source_commit"], "cve_ghsa": "",
                              "label_note": manifest_by_name[name].get("note", ""),
                              "label": int(lab), "_key": rec["finding_key"]})
                rows.append(feats)
                kept += 1
        print(f"  {name}: {kept} labeled rows kept, {dropped} dropped/ambiguous")
    return rows


def validate(rows):
    assert rows, "no rows produced — refusing to write an empty dataset"
    binary = {"is_string_concat", "is_parameterized_query", "has_sanitizer_nearby",
              "in_test_file", "is_in_vendor_or_generated_dir", "is_user_input_direct",
              "has_type_validation", "is_third_party_lib_call",
              "developer_dismissed_similar_before", "is_authenticated_endpoint"}
    for i, r in enumerate(rows):
        for c in RAW_FEATURES + ["label"]:
            assert c in r, f"row {i} missing column {c}"
            assert r[c] is not None and r[c] != "", f"row {i} col {c} empty"
        for c in binary:
            assert r[c] in (0, 1), f"row {i} col {c} not binary: {r[c]}"
        assert r["label"] in (0, 1), f"row {i} bad label {r['label']}"
        assert r["source_kind"] in ("cve_pair", "manual"), f"row {i} bad provenance"
    # no exact-duplicate rows (same finding scanned twice)
    keys = [(r["rule_id"], r["source_repo"], r["source_commit"],
             r.get("_key", "")) for r in rows]
    assert len(set(keys)) == len(keys), "duplicate rows detected"
    n1 = sum(r["label"] == 1 for r in rows)
    print(f"validated {len(rows)} rows: {n1} REAL / {len(rows)-n1} FALSE_POSITIVE, "
          f"no synthetic rows (builder has no generator)")


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--work-dir", default=os.path.expanduser("~/workspace/tmp-work/day8-datasets"))
    args = ap.parse_args()
    os.makedirs(args.work_dir, exist_ok=True)
    manifest = json.load(open(os.path.join(BASE_DIR, "sources.json"), encoding="utf-8"))

    if args.scan:
        for src in manifest["sources"]:
            print(f"scanning {src['name']} ({src['kind']}) ...")
            if src["kind"] == "cve_pair":
                # labels are automatic at --build time; just verify the pair resolves
                repo_root = ensure_clone(src["repo"], args.work_dir, src["name"])
                vuln = sh(["git", "-C", repo_root, "rev-parse", f"{src['fix_commit']}^"]).stdout.strip()
                print(f"  pair resolves: vuln={vuln[:12]} fix={src['fix_commit'][:12]}")
            else:
                scan_manual(src, args.work_dir)

    if args.build:
        rows = build_rows(args.work_dir)
        validate(rows)
        cols = RAW_FEATURES + ["label"] + PROVENANCE_COLS
        with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {OUT_CSV} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
