# Day-8 real dataset

The FP classifier's `v1_synthetic` weights were trained on 8,000 synthetic rows
from `generate_sample_data.py`. This directory holds the **real** replacement:
findings from the project's own scanner (`backend/utils/securityScanner.js`)
run over real open-source code, labeled by a human reviewer reading each
finding's code context.

## Files

- `sources.json` — provenance manifest. Every source: repo URL, pinned commit,
  kind (`manual` = expert-labeled; `cve_pair` = vulnerable/fix commit pair
  with automatic labels from fix-diff overlap). Includes the label semantics.
- `build_real_dataset.py` — the collector. `--scan` runs the scanner over all
  sources (manual sources dump findings to `review/`); `--build` assembles
  `real_findings.csv` from scans + `labels/*.csv`, validating the schema
  against `feature_schema.py`. Has no generator — it cannot emit a synthetic row.
- `review/<name>.jsonl` — every SAST finding per source with ±12 lines of code
  context and the 18 extracted features, for the reviewer.
- `labels/<name>.csv` — reviewer labels: `finding_key,label` where label is
  `1` (REAL), `0` (FALSE_POSITIVE), or `drop` (ambiguous — excluded).
- `real_findings.csv` — the dataset: 18 `RAW_FEATURES` + `label` + provenance
  columns (`source_kind`, `source_repo`, `source_commit`, `cve_ghsa`, `label_note`).
- `feedback_errors.csv` — dev-split misclassifications from the retrain's
  feedback loop (written by `real_data_retrain.py`).
- `evaluation_report.json` — held-out test metrics: v1_synthetic baseline vs v2
  before/after the feedback pass, plus the safety-gate decision.

## Label semantics

- `1` REAL — the scanner fired **and** the reviewer verified the code is
  actually exploitable (e.g. raw SQL string-concat with unsanitized request
  input reaching the query).
- `0` FALSE_POSITIVE — the scanner fired **but** the reviewer verified the code
  is safe (parameterized query, sanitizer/validator on the path, test fixture,
  or otherwise not reachable with attacker input).

When in doubt the reviewer drops the finding — a wrong label teaches the model
a lie, a dropped finding only costs a row.

## Rebuilding

```bash
python3 build_real_dataset.py --scan        # re-scan sources -> review/
# ... fill in labels/<name>.csv ...
python3 build_real_dataset.py --build       # -> real_findings.csv (validated)
python3 ../real_data_retrain.py             # train / feedback loop / gate
```

Feature enrichment mirrors `backend/routes/scans.js`: `rule_id` via the same
`RULE_MAP`, `file_change_frequency` via `git log` (capped at 50),
`same_finding_seen_before_count` / `developer_dismissed_similar_before` = 0
(no production DB — a fresh finding has no history).
