# recidivism

Utilities for downloading OSV data, enriching vulnerabilities with a recidivism
metric, and cloning referenced source repositories locally.

## Scripts

### 1) Download + enrich OSV vulnerabilities

```bash
python scripts/enrich_osv_recidivism.py \
  --output data/osv_recidivism.jsonl
```

This script:
- downloads the OSV dump (`OSV-all.zip` by default),
- extracts all vulnerabilities,
- computes a recidivism metric using CWE recurrence and repository/fix history,
- appends recidivism details to each vulnerability and writes JSONL output.

### 2) Clone OSV referenced repositories

```bash
python scripts/clone_osv_repositories.py \
  --osv-dir data/osv_dump \
  --target-dir data/repos \
  --update-existing
```

This script scans OSV vulnerabilities for GitHub source references and
clones/updates local copies for research workflows.
