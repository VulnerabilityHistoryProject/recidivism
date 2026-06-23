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

Configuration options in the .ini file can be overridden at runtime using command line (see examples below)

## Scripts

### 1) Download your OSV dump file

```bash
python scripts/dump_osv.py
```

This script:
- downloads the OSV dump (`OSV-all.zip` by default),
- extracts all vulnerabilities,
- computes a recidivism metric using CWE recurrence and repository/fix history,
- appends recidivism details to each vulnerability and writes JSONL output.

If you want to customize these at runtime, you can use the command line like this:

```bash
python scripts/dump_osv.py --osv-dump-url=https://storage.googleapis.com/osv-vulnerabilities/RubyGems/all.zip
```

### 2) Clone OSV referenced repositories (SKIP THIS STEP FOR NOW)

(Leaving this documentation in for now until we add this step back in)

```bash
python scripts/clone_osv_repositories.py \
  --osv-dir data/osv_dump \
  --target-dir data/repos \
  --update-existing
```

This script scans OSV vulnerabilities for GitHub source references and
clones/updates local copies for research workflows (organized as
`<target-dir>/<owner>/<repo>`).

This command runs the script and removes empty directories without user
prompts.

### 4) (Re)generate recidivism scores

```bash
python scripts/collect_recidivism.py
```

This script:
- scans the `OSV-all.zip` for all vulnerabilities in json files
- calculates a recidivism score for each vulnerability, as available
- updates the JSONL in `scores.output` config with severity scores
- (re)generates individual JSON files in `data/scores/<vulnerability_id>.json` containing:
  - recidivism string (TBD)

