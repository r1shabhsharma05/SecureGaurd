import os
import csv
import hashlib
import json
import urllib.request
import urllib.error

# Setup directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(os.path.dirname(BASE_DIR))
ENV_PATH = os.path.join(BACKEND_DIR, ".env")

# Define CSV files
SAMPLE_FINDINGS_CSV = os.path.join(BASE_DIR, "sample_findings.csv")
SYNTHETIC_FINDINGS_CSV = os.path.join(BASE_DIR, "synthetic_findings.csv")

def load_env(path):
    env = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    parts = line.split("=", 1)
                    k = parts[0].strip()
                    v = parts[1].strip().strip("'").strip('"')
                    env[k] = v
    return env

# The feedback export currently carries no finding id, organization, or
# labeler (see backend/routes/scans.js export-feedback: it emits only the
# 18 feature fields + label). Until it does, entries are deduped on a
# hash of their full feature vector + label, and provenance is recorded
# from the export whenever it provides it, else "unknown".
PROVENANCE_FIELDS = ("source_organization_id", "labeler_id")
# Export key spellings accepted for provenance, in preference order.
PROVENANCE_KEYS = {
    "source_organization_id": ("organization_id", "organizationId", "org_id"),
    "labeler_id": ("labeler_id", "labeled_by", "user_id"),
}


def _row_key(row, fieldnames):
    """Stable identity of one training row: hash of its feature values +
    label. Used to dedup feedback against the base set and within a batch
    (no finding id exists in the export to key on instead)."""
    payload = {f: str(row.get(f, "")) for f in fieldnames}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _provenance(entry, field):
    for key in PROVENANCE_KEYS[field]:
        value = entry.get(key)
        if value not in (None, ""):
            return str(value)
    return "unknown"


def _valid_label(entry):
    """A training label is valid only if it is exactly 0 or 1 (int, or
    the strings "0"/"1"). Anything else — missing, empty, 2, "real" —
    is rejected, never coerced into a training row."""
    label = entry.get("label")
    if isinstance(label, bool):
        return None
    if isinstance(label, int) and label in (0, 1):
        return label
    if isinstance(label, str) and label.strip() in ("0", "1"):
        return int(label.strip())
    return None


def main():
    print("[Data Collection] Loading configuration...")
    env = load_env(ENV_PATH)
    
    port = env.get("PORT", "5000")
    backend_url = f"http://localhost:{port}"
    api_key = env.get("CLASSIFIER_API_KEY", "")
    
    # 1. Back up sample_findings.csv to synthetic_findings.csv if not exists
    if os.path.exists(SAMPLE_FINDINGS_CSV) and not os.path.exists(SYNTHETIC_FINDINGS_CSV):
        print(f"[Data Collection] Backing up base findings to {SYNTHETIC_FINDINGS_CSV}...")
        os.rename(SAMPLE_FINDINGS_CSV, SYNTHETIC_FINDINGS_CSV)
    
    # Ensure synthetic seed exists
    if not os.path.exists(SYNTHETIC_FINDINGS_CSV):
        print(f"[Data Collection ERROR] Base dataset {SYNTHETIC_FINDINGS_CSV} not found!")
        return

    # 2. Fetch feedback from backend API
    url = f"{backend_url}/api/scans/export-feedback"
    headers = {
        "Content-Type": "application/json",
    }
    if api_key:
        headers["X-SecureGuard-Key"] = api_key

    print(f"[Data Collection] Fetching labeled findings from {url}...")
    req = urllib.request.Request(url, headers=headers)
    
    try:
        with urllib.request.urlopen(req) as response:
            feedback_data = json.loads(response.read().decode("utf-8"))
            print(f"[Data Collection] Successfully retrieved {len(feedback_data)} feedback entries.")
    except urllib.error.URLError as e:
        print(f"[Data Collection ERROR] Failed to connect to backend: {e}")
        print("[Data Collection] Defaulting to synthetic findings only.")
        feedback_data = []

    # 3. Read base synthetic findings
    synthetic_rows = []
    with open(SYNTHETIC_FINDINGS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            synthetic_rows.append(row)

    # 4. Combine findings: feedback entries are validated, deduped, and
    # provenance-stamped before they may join the training set.
    print(f"[Data Collection] Combining {len(synthetic_rows)} synthetic samples with {len(feedback_data)} feedback samples...")

    seen_keys = {_row_key(row, fieldnames) for row in synthetic_rows}
    combined_rows = list(synthetic_rows)
    n_added = n_duplicate = n_invalid = 0
    for entry in feedback_data:
        if not isinstance(entry, dict):
            n_invalid += 1
            continue
        label = _valid_label(entry)
        if label is None:
            n_invalid += 1
            print(f"[Data Collection] Skipping feedback entry with invalid label: {entry.get('label')!r}")
            continue
        # Construct clean row matching CSV headers
        row = {}
        for field in fieldnames:
            row[field] = str(entry.get(field, ""))
        row["label"] = str(label)
        key = _row_key(row, fieldnames)
        if key in seen_keys:
            n_duplicate += 1
            continue
        seen_keys.add(key)
        for field in PROVENANCE_FIELDS:
            row[field] = _provenance(entry, field)
        combined_rows.append(row)
        n_added += 1
    print(f"[Data Collection] Feedback: {n_added} added, {n_duplicate} duplicates skipped, {n_invalid} invalid labels skipped.")

    # 5. Overwrite sample_findings.csv (provenance columns appended;
    # retrain.py selects FEATURE_COLS + label, so the extra columns are
    # ignored by training and serve audit only).
    out_fieldnames = list(fieldnames)
    for field in PROVENANCE_FIELDS:
        if field not in out_fieldnames:
            out_fieldnames.append(field)
    with open(SAMPLE_FINDINGS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=out_fieldnames, restval="unknown")
        writer.writeheader()
        writer.writerows(combined_rows)

    print(f"[Data Collection] Successfully wrote {len(combined_rows)} total samples to {SAMPLE_FINDINGS_CSV}!")

if __name__ == "__main__":
    main()
