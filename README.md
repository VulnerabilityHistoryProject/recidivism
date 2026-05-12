# recidivism

Utilities for downloading OSV data, enriching vulnerabilities with a recidivism
metric, and cloning referenced source repositories locally.

## Configuration

Copy the default config and edit your local paths:

```bash
cp recidivism.default.ini recidivism.ini
```

Both scripts read settings from `recidivism.ini`. If that file is missing, the
scripts print guidance and fall back to `recidivism.default.ini`.

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
clones/updates local copies for research workflows (organized as
`<target-dir>/<owner>/<repo>`).
