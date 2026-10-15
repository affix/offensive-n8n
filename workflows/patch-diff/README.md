# Patch diff pipeline

The **patch diff pipeline** watches products we care about for new releases, diffs each new version against the last one and points out the changes that look like security fixes. It handles source repositories as well as compiled artefacts (ELF, PE, Mach-O, JAR, .NET, firmware, MSI, deb and rpm), scores every changed hunk or function for security signals, checks the result against published advisories and asks a local LLM what it makes of the strongest candidates. Anything that looks like a fix with no matching advisory is flagged as a **silent fix**, which is the interesting case: a vendor patching a bug without telling anyone.

## How the pipeline fits together

The *Watcher* runs every hour. It reads the `pd_watch` table, resolves the latest version of each enabled product from wherever that product publishes releases, and compares it with what `pd_versions` already knows. The first time it sees a product it only records a baseline. After that, a newer version starts an *Orchestrator* run diffing the previous version against the new one.

The *Orchestrator* takes a per-product lock, writes a run directory under `/opt/loot/patchdiff/<product>/<run_id>/` with a `config.json` built from the `pd_watch` row, and passes the run through five stage sub-workflows: Fetch, Unpack, Diff, Triage and Alerts. As with the ASM pipeline, the stages do not run tools from n8n directly. Each one builds a short script that calls `pd <stage>` (installed by the `patchdiff` role) and hands it to the *Job Runner*, which launches it detached under `timeout`, polls for completion and returns the stage's `result.json`. A stage that fails is routed to *Finish Run*, so the run is still recorded in `pd_runs` and the lock is released.

Ghidra analysis is heavy for a Raspberry Pi, so a product can set `"remote": true` in its options. The Orchestrator then asks the *Worker* to bring up a DigitalOcean droplet from the latest `pd-worker-*` snapshot (built with [`pd-worker`](../../pd-worker/README.md)), runs Fetch, Unpack and Diff on it over SSH, pulls the results back and tears the droplet down. Triage and Alerts always run on the Pi, because they need Ollama and Postgres.

*Housekeeping* keeps the loot directory and cache under control, and the *Error Handler* posts any unhandled failure to Discord. The Orchestrator, Watcher, Worker and Housekeeping all name the Error Handler as their `errorWorkflow`.

## What each workflow does

### PD · Orchestrator (`orchestrator.json`)

This workflow has two entry points: an *Execute Workflow* trigger used by the Watcher, and an n8n form at `/form/pd-run` that diffs two named versions of a product. The form requires an n8n login and only accepts products that already exist in `pd_watch`, whether they are enabled or not.

*Prepare Run* loads the product's `pd_watch` row, checks that `artefact_kind` is one we know how to handle, parses `options` as JSON and works out the stage time limits. *Prepare Run Dir* creates the run directory, writes `config.json` and takes the lock (`<product>/.lock`, created with `mkdir`). If the product is already locked the run is skipped, and a lock older than 16 hours is treated as stale and taken over. The run is recorded in `pd_runs` and each stage updates the `stage` column as it starts, so a run that dies shows where it got to.

*Finish Run* works out the final status (`ok`, `partial` if any stage timed out, or `failed`), writes it back to `pd_runs`, marks the version in `pd_versions` as diffed or failed, releases the lock and, for remote runs, tears the worker down. It only posts to Discord when a run failed or a stage timed out. Successful runs are reported by the Alerts stage.

Data tables: reads `pd_watch`, writes `pd_runs` and `pd_versions`.

### PD · Job Runner (`job-runner.json`)

The Job Runner is called by every stage with `job_dir`, `script`, `max_minutes` and an optional `remote_host`. It refuses any `job_dir` that does not match `/opt/loot/patchdiff/<product>/<run_id>/<stage>` and caps `max_minutes` at 720. It writes the script to `job.sh`, starts it detached under `timeout`, and polls for a done marker. With `remote_host` set, the same thing happens on the worker over SSH using the run's key in `/dev/shm/pd-ssh/<run_id>`. Exit code 124 is reported as timed out with partial results, and any other non-zero exit code throws with the tail of the job log.

Host tools: `bash`, `setsid`, `timeout`, `base64`, `jq`, `ssh`.

### PD · Fetch (`01-fetch.json`)

This stage runs `pd fetch`, which gets both versions into `_cache/<product>/`. For binary kinds it expands `artefact_url_template` for each version, downloads the artefacts with size caps and records their SHA-256. For `source` it clones or updates the repository instead. Artefacts dropped into `_inbox/<product>/` by hand are used as they are, which covers vendors that put downloads behind a login. Default time limit 60 minutes.

### PD · Unpack (`02-unpack.json`)

This stage runs `pd unpack`, which extracts both artefacts and picks the files worth diffing with `binary_globs`. Plain zip, tar and deb archives are extracted on the host; anything else is unpacked by unblob in a container with `--network none`. JARs and APKs are decompiled with jadx and .NET assemblies with ilspycmd, so they can be diffed as source. The chosen targets are written to `targets.json`. Default time limit 90 minutes.

### PD · Diff (`03-diff.json`)

This stage runs `pd diff`. Source and decompiled trees are diffed hunk by hunk. Native binaries go through ghidriff against a persistent Ghidra project per product, so a version only has to be analysed once, with a host-wide lock so two diffs never fight over the JVM's memory. Every changed hunk or function is scored for security signals (bounds checks, length validation, integer overflow guards, auth and path handling and similar) and written to `candidates.json`. Default time limit 240 minutes.

### PD · Triage (Ollama) (`04-triage-ollama.json`)

This workflow runs two jobs. `pd advisory` pulls advisories for the new version from the product's `advisory_feed` (a vendor RSS or Atom feed, GitHub security advisories for a repository or package, or NVD CVEs for a CPE) and marks the candidates they plausibly cover. `pd triage` then sends up to 25 of the top candidates to a local Ollama model, which returns a bug class, a one-line summary, a confidence, a likely entry point and a 0 to 100 `likely_security_fix` score. Triage is advisory only and never drops a candidate. If the model is unreachable or replies with something unparseable, the candidate is kept untriaged.

### PD · Alerts (`05-alerts.json`)

This stage creates the `pd_findings` table in Postgres if it does not exist, then inserts the run's candidates keyed on a stable finding key, so a change already reported for an earlier run is not reported again. A candidate is a silent fix when the model's `likely_security_fix` is at or above `silent_fix_threshold` (60 unless the product overrides it) and no advisory matched it. The stage posts one Discord summary per run with the top five candidates, and a separate message for any new silent fixes.

Postgres: creates and writes `pd_findings`.

### PD · Watcher (`watcher.json`)

This runs every hour at minute 23, and can also be run by hand or from the form at `/form/pd-check`, which checks one product whether it is enabled or not. For each product it builds a lookup from `source_type` and `source_ref` (see the `pd_watch` table below), pulls the version list, filters it with `version_regex`, drops pre-releases unless `include_prerelease` is set and takes the highest version with a version-aware comparison. A product that cannot be resolved posts to Discord at most once a day.

Data tables: reads `pd_watch`, reads and writes `pd_versions`.

### PD · Worker (`worker.json`)

The Worker is called by the Orchestrator with `op` set to `up`, `pull` or `down`, and does nothing for products without `"remote": true`. On `up` it generates an ed25519 key for the run in `/dev/shm` (RAM only), finds the latest `pd-worker-*` snapshot, limits the `pd-worker` firewall to SSH from the Pi's current public IP, and creates a droplet tagged `pd-run-<run_id>` with that key in its cloud-init. It waits for the droplet to come up, pins its host key on first contact and copies `config.json` across. On `pull` it copies the fetch, unpack and diff results back, leaving the unpacked artefacts and decompiled trees on the worker. On `down` it deletes the droplet by tag and removes the key, and posts to Discord if the delete fails.

A reaper runs every hour at minute 41 and deletes any `pd-worker` droplet older than 24 hours, in case a run died without tearing its worker down.

The Worker expects a few things to exist in the DigitalOcean account already: a firewall named `pd-worker` applied to the `pd-worker` tag, an SSH key named `pd-worker-bootstrap`, a project to put the droplets in, and at least one `pd-worker-*` snapshot in the region you want.

### PD · Housekeeping (`housekeeping.json`)

This runs nightly at 03:47 and can also be run by hand. It runs `pd housekeeping`, which compresses runs older than 14 days (always keeping the latest three per product), prunes cached versions that no run references, clears stale locks, checks that the pinned images are present and warns when free disk drops below 10GB. It posts to Discord when something needs attention, every Monday as a summary, and whenever it is run by hand.

### PD · Error Handler (`error-handler.json`)

This is the error workflow for the pipeline. It formats the failed execution and posts it to the alerts channel.

## What the host needs

Everything the stages run comes from the `ghidra` and `patchdiff` roles, so set `ghidra_enabled` and `patchdiff_enabled` and re-run the playbook. That gives us Ghidra, the `pd` wrapper, the unpacking and decompiling tools and the `/opt/loot/patchdiff` layout. The Alerts stage needs the `postgres` role enabled as well, and Triage needs an Ollama server reachable at `patchdiff_ollama_url`.

Remote runs also need a `pd-worker-*` snapshot in DigitalOcean, built with [`pd-worker`](../../pd-worker/README.md), and the DigitalOcean setup described under the Worker above.

## Creating the data tables

Create these three tables in n8n before importing. Column names must match exactly.

### pd_watch

One row per product we watch.

| Column | Type | Purpose |
|---|---|---|
| `product` | string | Short name, lowercase letters, digits, `_` and `-`, up to 40 characters. Used in paths. `pd-sys` is reserved. |
| `enabled` | boolean | Whether the Watcher checks this product every hour. |
| `source_type` | string | Where versions are published: `github_release`, `git_tags`, `registry`, `docker_tag`, `rss`, `vendor_page` or `inbox`. |
| `source_ref` | string | What to look up. `owner/repo` (or a GitHub URL) for `github_release` and `git_tags`, any HTTPS git URL for `git_tags`, `<eco>:<package>` for `registry` (`pypi`, `npm`, `crates`, `nuget`, `maven` as `group:artifact`, `packagist`, `rubygems`, `go`), an image name for `docker_tag`, or a URL for `rss` and `vendor_page`. |
| `version_regex` | string | Optional filter applied to version strings before the highest one is chosen. |
| `selector` | string | CSS selector for `vendor_page`. Defaults to every link. |
| `artefact_kind` | string | `source`, `elf`, `pe`, `macho`, `jar`, `dotnet`, `firmware`, `msi`, `deb` or `rpm`. |
| `artefact_url_template` | string | Download URL with `{version}` (and `{vdir}` where the vendor needs it). Not needed for `source` or `inbox`. |
| `binary_globs` | string | Which unpacked files to diff. Each kind has sensible defaults. |
| `advisory_feed` | string | Where to look for advisories, separated by `\|` or newlines: an RSS or Atom URL, `ghsa:<owner>/<repo>`, `ghsa-eco:<eco>:<pkg>` or a `cpe:2.3:` string. |
| `max_artefact_mb` | number | Download size cap. |
| `max_unpacked_mb` | number | Unpacked size cap. |
| `options` | string | JSON object of extra settings, described below. |
| `notes` | string | Free text. |

`options` can hold `remote` (run Fetch, Unpack and Diff on a DigitalOcean worker), `do_size` and `do_region` (defaults `c-8` and the snapshot's region), `include_prerelease`, `silent_fix_threshold`, and `fetch_max_minutes`, `unpack_max_minutes`, `diff_max_minutes` and `triage_max_minutes` to change the stage time limits. Anything else in it is passed through to the stage scripts in `config.json`.

### pd_versions

Every version the Watcher has seen. Written by the Watcher and updated by the Orchestrator.

| Column | Type |
|---|---|
| `product` | string |
| `version` | string |
| `seen_at` | date |
| `artefact_path` | string |
| `sha256` | string |
| `status` | string |

### pd_runs

One row per Orchestrator run.

| Column | Type |
|---|---|
| `run_id` | string |
| `product` | string |
| `old_version` | string |
| `new_version` | string |
| `trigger` | string |
| `run_dir` | string |
| `started_at` | date |
| `finished_at` | date |
| `status` | string |
| `stage` | string |
| `candidates` | number |
| `silent_fixes` | number |
| `error` | string |

The `pd_findings` Postgres table does not need creating by hand, because the Alerts stage creates it and its indexes on the first run.

## Importing the workflows

The exports keep their original workflow IDs, so the *Execute Workflow* references between them resolve as long as everything is imported into the same instance. That also means an import overwrites any existing workflow with the same ID. Import the sub-workflows first so the callers find them. A sensible order is the Job Runner, the Error Handler, the Worker, Fetch, Unpack, Diff, Triage and Alerts, then the Orchestrator, the Watcher and Housekeeping. The `errorWorkflow` setting on the top-level workflows points at the Error Handler's ID (`PpGzaQp9DxQSRshR`). If you import the Error Handler under a different ID, re-select it in each workflow's settings.

The exports have been scrubbed of anything specific to the original instance, so a few placeholders need filling in before the first run:

| Placeholder | Where | What to do |
|---|---|---|
| `DATA_TABLE_<name>` | Every Data table node | Re-select the matching table (`pd_watch`, `pd_versions`, `pd_runs`) from the list. |
| `CREDENTIAL_ID` | Discord, Postgres and DigitalOcean nodes | Create and select a **Discord Bot** credential (*Discord Bot account*), a **Postgres** credential (*Postgres account*) pointing at the `postgres` role's database, and an **HTTP Bearer Auth** credential (*DO Token*) holding a DigitalOcean API token. The token needs read and write access to droplets, firewalls and projects, and read access to snapshots and SSH keys. |
| `DISCORD_GUILD_ID`, `DISCORD_ALERTS_CHANNEL_ID` | Every Discord node | Pick your server and alert channel. |
| `DO_PROJECT_ID` | *Plan* in the Worker | The UUID of the DigitalOcean project worker droplets are assigned to. |

The Ollama endpoint and model are not in the workflows. The Triage stage reads them from `/opt/patchdiff/etc/tools.json`, which the `patchdiff` role writes from `patchdiff_ollama_url` and `patchdiff_ollama_model`.

Once the placeholders are set, add a product to `pd_watch` and run the Watcher with *Check Now* or the `/form/pd-check` form. The first check only records a baseline. To see a diff straight away, use the `/form/pd-run` form with two versions you already know.
