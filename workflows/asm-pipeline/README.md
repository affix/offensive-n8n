# ASM pipeline

The **ASM pipeline** is an external attack surface monitor built out of n8n workflows and the usual ProjectDiscovery tooling. It takes a scope you define in an n8n data table, discovers what is exposed, fingerprints it, works out what has changed since the last run, and only then points vulnerability checks at the new or changed assets. Anything new gets recorded, scored by a local LLM and posted to Discord. The idea is that it runs every six hours against authorised engagements and stays quiet unless something actually moved.

## How the pipeline fits together

Everything starts at the *Orchestrator*. It reads `asm_scope`, drops engagements that are disabled, out of date range or outside their testing window, validates every asset, and builds a per-engagement run directory under `/opt/loot/asm/<engagement>/<run_id>/`. Before a run starts it takes a lock on the engagement, so two runs never scan the same target set at the same time.

Each engagement then goes through seven stage sub-workflows in order: Discovery, Takeover Check, Port Scan, Web Fingerprint, Diff, Vuln Checks and Findings & Alerts. The stages do not run tools directly from n8n. Each one builds a bash script and hands it to the *Job Runner*, which launches it detached on the host with `setsid` and `timeout`, polls for completion and returns the stage's `result.json`. This keeps long scans from tripping n8n's own execution timeouts and means a scan survives a slow poll. A stage that fails is routed down its error output to *Finish Run*, so the run is still closed out in `asm_runs`, the lock is released and the failure is posted.

A few supporting workflows sit alongside the main run. *CVE Watch* matches new CVEs and the CISA KEV catalogue against what the pipeline has fingerprinted, *Housekeeping* keeps the evidence directory and tooling healthy, *Scope Expiry Watch* switches off engagements whose scope has ended, and the *Error Handler* posts any unhandled failure to Discord. The Orchestrator, CVE Watch, Housekeeping and Scope Expiry Watch all name the Error Handler as their `errorWorkflow`. The stage sub-workflows do not, because their errors are caught by the Orchestrator.

## What each workflow does

### ASM · Orchestrator (`orchestrator.json`)

This workflow has three triggers: a schedule every six hours (at minute 41), a manual *Run All Now*, and an n8n form at `/form/asm-run` that runs a single named engagement. The form requires an n8n login and only accepts engagements that already exist and are enabled in `asm_scope`. It will not take ad-hoc targets.

*Scope Dates* drops engagements whose `scope_start` is in the future or whose `scope_end` has passed. *Scope Gate* then groups the remaining rows by engagement and validates each asset against its type. CIDRs wider than a /16 are refused (exclusions can be any width), invalid entries are reported as warnings, and an engagement outside its `window_start_utc`/`window_end_utc` window is skipped. It also works out the rate limit, whether intrusive checks are allowed, and whether permutations are on (see the `asm_scope` table below). It writes the scope files and a small `scope.py` helper into the run directory. Every later stage uses that helper to keep results in scope.

*Prepare Run Dir* creates the run directory and takes the lock (`<engagement>/.lock`, created with `mkdir`). If the engagement is already locked, that engagement is skipped. A lock older than 16 hours is treated as stale and taken over. The run is recorded in `asm_runs` and passed through the seven stages. *Finish Run* builds a summary and *Update Run* writes it back to `asm_runs`. *Release Lock* removes the lock, and the summary is posted to Discord if the run failed, was started by hand, set a baseline, found new or changed assets, produced alertable findings or had a stage time out.

Data tables: reads `asm_scope`, writes `asm_runs`.

### ASM · Job Runner (`job-runner.json`)

The Job Runner is called by every stage with `job_dir`, `script` and `max_minutes`. It refuses any `job_dir` that does not match `/opt/loot/asm/<engagement or _sys>/<timestamp>-<rand>/<stage>`. It caps `max_minutes` at 600 and limits the script size so it fits on one command line. It writes the script to `job.sh` and starts it with `setsid nohup timeout <n>m bash job.sh`, then polls every five seconds for a `.done` marker. Exit code 124 (timeout) is reported as `timed_out` with partial results rather than as a failure. Any other non-zero exit code throws with the tail of `job.log`.

Host tools: `bash`, `setsid`, `timeout`, `base64`, `jq`.

### ASM · 01 Discovery (`01-discovery.json`)

This stage runs `subfinder` against the root domains, adds explicitly scoped hosts and filters everything back through the scope helper. If permutations are enabled for the engagement, it runs `alterx` (Docker) and filters again. It then resolves the names with `dnsx` (A and CNAME records) and expands scoped CIDRs with `mapcidr` (Docker).

It also sorts the resolved hosts into groups. A host whose CNAME leaves scope, or that resolves into the AWS S3 or API Gateway ranges (fetched from `ip-ranges.amazonaws.com` and cached for a day), is marked as a shared **service** and gets no IP scans or vuln checks. A host behind a CDN or WAF edge, detected with `cdncheck` (Docker), is marked as **edge**. Edge hosts get no IP scans, but their hostname still gets web checks. IPs you scoped explicitly are never dropped.

Outputs: `hosts.txt`, `ips.txt`, `cname_hosts.txt`, `host_ip.json` and `shared_hosts.txt` in `discovery/`. Time limit 120 minutes.

### ASM · 02 Takeover Check (`02-takeover-check.json`)

This stage runs `nuclei -tags takeover -dr` against every host that discovery saw with a CNAME. The `-dr` flag stops nuclei following redirects off the host. Results are normalised into `findings/takeover.jsonl`. Time limit 60 minutes.

### ASM · 03 Port Scan (`03-port-scan.json`)

This stage runs a `naabu` SYN scan of the top 1000 ports on the in-scope IPs, with `-exclude-cdn` set. The port rate is the engagement rate times ten, between 100 and 1000. Only the ip:port pairs not already in the engagement's `state/ports.txt` go on to `nmap -sV -sC`, one host at a time with a 12-minute host timeout. Both scanners run as `sudo -n /usr/bin/naabu` and `sudo -n /usr/bin/nmap`. Outputs are `ports/open.txt` and `ports/services.jsonl`. Time limit 240 minutes.

### ASM · 04 Web Fingerprint (`04-web-fingerprint.json`)

This stage builds a target list from the discovered hostnames, every open ip:port, host:port pairs for non-standard ports (up to 25 hostnames per IP) and any scoped URLs. It runs `httpx` from a pinned Docker image over that list. Each live URL gets a **fingerprint**: a hash of status code, title, detected technologies, server header, favicon hash and TLS certificate CN. Output is `web/web.jsonl`. Time limit 90 minutes.

### ASM · 05 Diff (`05-diff.json`)

This stage compares the run against the engagement's `state/` directory. New open ports and new or changed web fingerprints become the **delta**. The delta is what Vuln Checks scans, so unchanged assets are not re-scanned every six hours. The first run against an engagement is marked as a baseline. The state files are written atomically. *Persist Service State* also keeps the latest nmap services and httpx output in `state/` for CVE Watch to use. New and changed assets (up to 500 per run) are upserted into `asm_assets`, keyed on `asset_key`. Time limit 30 minutes.

Data tables: writes `asm_assets`.

### ASM · 06 Vuln Checks (`06-vuln-checks.json`)

This stage only works on the delta from Diff. Before any tool runs, it drops targets that discovery marked as shared service infrastructure, and IPs that are not in the scoped IP list. It then runs:

- `nuclei` at medium, high and critical severity, using the `cve`, `exposure`, `misconfig`, `default-login` and `takeover` tags. The `dos` and `fuzz` tags are always excluded, and `intrusive` is excluded unless intrusive checks are allowed.
- `ffuf` against a short built-in list of sensitive paths (VCS metadata, `.env` files, backups, Spring Actuator, API docs and so on), on up to 200 web targets.
- `katana` to crawl two levels deep and collect in-scope URLs that take parameters.

Only when the engagement allows intrusive checks does it run `nuclei -dast` and `dalfox` (Docker) against those parameterised URLs. Everything is normalised into `findings/vuln.jsonl`. Time limit 360 minutes.

### ASM · 07 Triage (Ollama) (`07-triage-ollama.json`)

This workflow is called by Findings & Alerts with the new findings. It sends up to 25 per run to a local Ollama model, which returns a false-positive likelihood from 0 (real) to 100 (noise) and a one-line note. The scores are advisory only: they are stored and shown in alerts, but they never suppress a finding. If the model is unreachable or replies with something unparseable, the finding is recorded as untriaged.

### ASM · 08 Findings & Alerts (`08-findings-alerts.json`)

This stage reads every `findings/*.jsonl` for the run and removes any `finding_key` already in `asm_findings` for that engagement. It triages what is left through stage 07 and inserts it into `asm_findings`. It posts one Discord embed per host (up to 20 hosts) for findings that are medium or above, or that came from the takeover check.

Data tables: reads and writes `asm_findings`.

### ASM · CVE Watch (`cve-watch.json`)

This runs daily at 07:23 and can also be run by hand. It builds an inventory for every enabled engagement from the nmap services (product and version) and the httpx technology detections kept in `state/`. It pulls the last two days of NVD changes and the CISA KEV catalogue (cached for 12 hours), and maps product names to CPE vendor and product pairs with a built-in alias table.

A match counts as **version-confirmed** when the observed version falls inside the CPE's vulnerable range. A KEV entry that matches the product but has no confirmed version is recorded at `info` severity and is not alerted. Distribution builds such as Ubuntu or Debian get a note to check for a backported fix. Older KEV entries for products in the inventory are looked up individually, up to 60 a run.

Each engagement, CVE and asset combination is alerted only once. The record of what has been alerted is kept in `/opt/loot/asm/_cache/cve_alerted.json`. If `NVD_API_KEY` is in the n8n process environment, the job uses it and waits less between NVD requests.

Data tables: reads `asm_scope`, writes `asm_findings`.

### ASM · Housekeeping (`housekeeping.json`)

This runs nightly at 03:17. It compresses run directories older than 14 days into `.tar.gz` files. It never compresses the latest run for an engagement, or a run with a job still in progress. It flags engagement locks older than 16 hours and marks `asm_runs` rows that have been `running` for more than 18 hours as `stale`. It also updates the nuclei templates, checks that the pinned Docker images are present and checks disk usage on `/opt/loot`. It posts to Discord when something needs attention, and posts a summary every Monday.

Data tables: reads and updates `asm_runs`.

### ASM · Scope Expiry Watch (`scope-expiry-watch.json`)

This runs daily at 07:52. It sets `enabled = false` on every `asm_scope` row of an engagement whose `scope_end` has passed, and warns three days before an end date. On Mondays it also lists enabled engagements that have no `scope_end`.

Data tables: reads and updates `asm_scope`.

### ASM · Error Handler (`error-handler.json`)

This is an error-trigger workflow. It posts the failing workflow, the node, the execution mode and ID, and the error message to Discord, with a link to the execution.

## What the host needs

The stages run on the same host as n8n through the **Execute Command** node. n8n 2.x disables that node by default, so it has to be allowed (for example by setting `NODES_EXCLUDE` to `[]`). The commands run as the n8n service user. That user needs:

- `subfinder`, `dnsx`, `nuclei`, `katana` and `ffuf` on its `PATH`.
- Passwordless sudo for exactly `/usr/bin/naabu` and `/usr/bin/nmap`, because SYN scans need raw sockets.
- Access to Docker, plus the pinned images `projectdiscovery/httpx:v1.12.0`, `projectdiscovery/alterx:v0.0.6`, `projectdiscovery/mapcidr:v1.1.16`, `projectdiscovery/cdncheck:v1.1.36` and `hahwul/dalfox:v2.12.0`.
- `python3` 3.10 or newer (standard library only), `jq`, `curl`, `gzip`, `tar` and the coreutils `timeout` and `setsid`.
- Write access to `/opt/loot/asm`.
- An Ollama instance reachable from n8n for stage 07, with the model you set as `OLLAMA_MODEL` already pulled.

Evidence and state are laid out like this:

```
/opt/loot/asm/
  _cache/                     AWS ranges, KEV and NVD caches, cve_alerted.json
  _sys/<stamp>-<rand>/<job>/  CVE Watch and Housekeeping jobs
  <engagement>/
    .lock                     present while a run is in progress
    state/                    ports.txt, web.json, services.json, web_latest.jsonl
    <stamp>-<rand>/           one directory per run
      scope/ discovery/ takeover/ ports/ web/ diff/ vuln/ findings/
```

## Creating the data tables

The pipeline keeps its scope, run history, asset inventory and findings in n8n **data tables** rather than Postgres, so there is nothing to install. We create each one in n8n under *Overview > Data tables* with exactly the name and columns below. Column names matter because the workflows map fields by name. n8n adds `id`, `createdAt` and `updatedAt` itself.

### asm_scope

This table is the scope of every engagement, one row per asset. The Orchestrator and CVE Watch read it, and Scope Expiry Watch updates it.

| Column | Type | Meaning |
|---|---|---|
| `engagement` | string | Engagement name, lowercase `a-z0-9_-`, up to 40 characters. Rows with the same name form one engagement. |
| `asset` | string | The target: a domain, `*.domain`, hostname, IP, CIDR or `http(s)://` URL. |
| `asset_type` | string | `domain`, `wildcard`, `host`, `ip`, `cidr` or `url`. Left blank, the type is inferred from `asset`. A `domain` or `wildcard` is enumerated for subdomains, while a `host` is only that name. CIDRs must be /16 or narrower. |
| `enabled` | boolean | Only rows with `true` are used. |
| `exclude` | boolean | When `true`, the row removes a name (and its subdomains), an IP or a range from scope instead of adding it. |
| `allow_intrusive` | boolean | Intrusive checks (intrusive nuclei templates, nuclei DAST, dalfox) only run when every non-exclude row of the engagement has this set to `true`. |
| `window_start_utc` | string | Optional start of the testing window, `HH:MM` UTC. |
| `window_end_utc` | string | Optional end of the testing window, `HH:MM` UTC. Windows that cross midnight work. A run outside the window is skipped. |
| `rate_limit` | number | Requests per second for nuclei, httpx, ffuf and katana. The engagement uses the lowest value across its rows, defaults to 50 and is clamped to 1 to 500. The naabu rate is ten times this, between 100 and 1000. |
| `permutations` | boolean | When any row is `true`, discovery also runs alterx permutations. |
| `scope_start` | date | Optional. The engagement does not run before this date. |
| `scope_end` | date | Optional. The engagement does not run after this date, and Scope Expiry Watch disables it. |
| `notes` | string | Free text, not read by the workflows. |

A small engagement might look like this:

| engagement | asset | asset_type | enabled | exclude | allow_intrusive | rate_limit | scope_end |
|---|---|---|---|---|---|---|---|
| example | example.com | domain | true | false | false | 50 | 2026-12-31 |
| example | 203.0.113.0/24 | cidr | true | false | false | 50 | 2026-12-31 |
| example | https://app.example.net/login | url | true | false | false | 50 | 2026-12-31 |
| example | legacy.example.com | host | true | true | false | | |

### asm_runs

This table holds one row per engagement run. The Orchestrator inserts and updates it, and Housekeeping marks stuck runs as `stale`.

| Column | Type |
|---|---|
| `run_id` | string |
| `engagement` | string |
| `trigger` | string |
| `stage` | string |
| `status` | string |
| `started` | date |
| `finished` | date |
| `hosts` | number |
| `assets_new` | number |
| `assets_changed` | number |
| `findings_new` | number |
| `out_dir` | string |
| `error` | string |

`trigger` is `schedule`, `manual` or `form`. `status` is `running`, `ok`, `failed` or `stale`. `stage` is the stage that failed, or `done`.

### asm_assets

This is the asset inventory, one row per open port (`kind = port`) or web endpoint (`kind = web`). `asset_key` is unique and has the form `<engagement>|port|<ip:port>` or `<engagement>|web|<url>`. Diff writes it.

| Column | Type |
|---|---|
| `asset_key` | string |
| `engagement` | string |
| `kind` | string |
| `host` | string |
| `ip` | string |
| `port` | number |
| `service` | string |
| `url` | string |
| `status_code` | number |
| `title` | string |
| `tech` | string |
| `fingerprint` | string |
| `first_seen` | date |
| `last_seen` | date |
| `run_id` | string |

### asm_findings

This table holds every finding the pipeline has seen. Findings & Alerts and CVE Watch write it, and Findings & Alerts reads it to skip duplicates. `finding_key` is unique per engagement, source, template and location. `source` is `takeover`, `nuclei`, `nuclei-dast`, `ffuf`, `dalfox` or `cve-watch`. New rows get `status = new`, which you can change as you work through them.

| Column | Type |
|---|---|
| `finding_key` | string |
| `engagement` | string |
| `run_id` | string |
| `source` | string |
| `host` | string |
| `url` | string |
| `template_id` | string |
| `name` | string |
| `severity` | string |
| `matched_at` | string |
| `evidence_dir` | string |
| `status` | string |
| `triage_fp_likelihood` | number |
| `triage_note` | string |
| `first_seen` | date |
| `last_seen` | date |

## Importing the workflows

The exports keep their original workflow IDs, so the *Execute Workflow* references between them resolve as long as everything is imported into the same instance. That also means an import overwrites any existing workflow with the same ID. Import the sub-workflows first so the callers find them. A sensible order is the Job Runner, the Error Handler, 07 Triage, stages 01 to 06 and 08, and finally the Orchestrator, CVE Watch, Housekeeping and Scope Expiry Watch. The `errorWorkflow` setting on the scheduled workflows points at the Error Handler's ID (`oTbFYlbhb8Dlg0CM`). If you import the Error Handler under a different ID, re-select it in each workflow's settings.

The exports have been scrubbed of anything specific to the original instance, so a few placeholders need filling in before the first run:

| Placeholder | Where | What to do |
|---|---|---|
| `DATA_TABLE_<name>` | Every Data table node | Re-select the matching table (`asm_scope`, `asm_runs`, `asm_assets`, `asm_findings`) from the list. |
| `CREDENTIAL_ID` | Discord nodes | Create a **Discord Bot** credential (named *Discord Bot account* in the exports) and select it. No other credentials are used in this folder. |
| `DISCORD_GUILD_ID`, `DISCORD_ALERTS_CHANNEL_ID` | Discord nodes in the Orchestrator, 08, CVE Watch, Housekeeping, Scope Expiry Watch and the Error Handler | Pick your server and alert channel. |
| `OLLAMA_HOST` | *Ask Ollama* in 07 Triage | Hostname or IP of your Ollama server (port 11434 is already in the URL). |
| `OLLAMA_MODEL` | *Build Prompts* in 07 Triage | The Ollama model to use, for example a small instruct model that can return JSON. |

Once the placeholders are set, add an engagement to `asm_scope` and start it from the *Run Engagement* form or with *Run All Now*. The first run sets the baseline, and runs after that only report what has changed.
