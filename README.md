# recidivism

Utilities for downloading OSV data, enriching vulnerabilities with a recidivism
metric, and cloning referenced source repositories locally.

## Scripts

### 1) Download + enrich OSV vulnerabilities

```bash
python /home/runner/work/recidivism/recidivism/scripts/enrich_osv_recidivism.py \
  --output /home/runner/work/recidivism/recidivism/data/osv_recidivism.jsonl
```

This script:
- downloads the OSV dump (`OSV-all.zip` by default),
- extracts all vulnerabilities,
- computes a recidivism metric using CWE recurrence and repository/fix history,
- appends recidivism details to each vulnerability and writes JSONL output.

### 2) Clone OSV referenced repositories

```bash
python /home/runner/work/recidivism/recidivism/scripts/clone_osv_repositories.py \
  --osv-dir /home/runner/work/recidivism/recidivism/data/osv_dump \
  --target-dir /home/runner/work/recidivism/recidivism/data/repos \
  --update-existing
```

This script scans OSV vulnerabilities for GitHub source references and
clones/updates local copies for research workflows.
