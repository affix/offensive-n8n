# Subdomain Takeover

A **subdomain takeover** happens when a DNS record (usually a CNAME) still points at a third-party service such as a cloud storage bucket or a SaaS landing page that has since been deleted, letting anyone who re-registers that resource serve content on the victim's hostname. These two workflows watch a list of root domains for exactly that, enumerating subdomains, keeping the ones with CNAMEs and running the nuclei takeover templates against them.

This is the standalone version of the check. The ASM pipeline in `../asm-pipeline` runs the same nuclei templates as its stage 02, scoped by engagement, so use whichever fits: this pair is lighter and only needs a list of domains.

## What does each workflow do?

### Subdomain Takeover Monitor

Runs every 4 hours, on demand with *Run Now*, or for a single domain through the **One-off Scan Form** (protected by n8n user auth, and the domain is not added to the scheduled scope).

On the schedule it reads every row from `takeover_scope`, drops disabled rows and anything that is not a strict hostname, and deduplicates. The domains are then dealt round-robin into at most 3 **lanes**, and one Subdomain Takeover Scan execution is started per lane. Each lane works through its domains one after another, so no more than 3 scans ever run at once regardless of how many domains are in scope.

The form path accepts a pasted URL, reduces it to the hostname, validates it and hands a single-entry lane to the same scan workflow, so one-off and scheduled scans behave identically.

### Subdomain Takeover Scan

A sub-workflow that takes `domains`, a list of `{domain, client}` objects. Domains are validated again here because any caller can hand it input and the values end up in a shell command.

For each domain it runs on the n8n host:

1. `subfinder` for passive subdomain enumeration.
2. `dnsx` to resolve them and record CNAME chains.
3. `nuclei -tags takeover` (rate limited to 25 requests per second) against only the hosts that have a CNAME.

Output lands in `/opt/loot/takeover/<domain>/<UTC timestamp>/` with the raw lists and each tool's log, and the command prints a JSON summary for the workflow to parse.

Findings are keyed on `host|template`, checked against `takeover_findings` so each one alerts only once, recorded, and posted to Discord with one embed per host. The embed is coloured by the worst severity and distinguishes a plain dangling CNAME (the target no longer resolves, so check whether it can be registered) from a confirmed service fingerprint. A domain whose scan fails gets its own failure embed pointing at the log directory, and the rest of the lane carries on.

## What does the host need?

The Execute Command node must be enabled in n8n, and the n8n service user needs `subfinder`, `dnsx`, `nuclei` and `jq` on its `PATH` plus write access to `/opt/loot/takeover`. The `tooling` role in this repo installs all of them. Subfinder works without API keys but finds far more with them configured in its provider config.

## Creating the data tables

Create these under **Overview > Data tables** in n8n before importing. Names must match exactly.

### `takeover_scope`

The root domains to monitor. Read by the Monitor.

| Column | Type | Meaning |
|---|---|---|
| `domain` | string | Root domain, for example `example.com`. Subdomains are discovered, so do not list them. |
| `enabled` | boolean | Rows set to `false` are skipped. Blank counts as enabled. |
| `client` | string | Optional label shown in alerts, useful when watching domains for several organisations. |
| `notes` | string | Free text, not read by the workflows. |

### `takeover_findings`

One row per finding, used to make sure each finding is only alerted once. Written by the Scan.

| Column | Type | Meaning |
|---|---|---|
| `finding_key` | string | `host|nuclei template ID`, the dedupe key. |
| `domain` | string | Root domain the host was found under. |
| `host` | string | Affected hostname. |
| `cname` | string | CNAME chain recorded by dnsx. |
| `template_id` | string | nuclei template that matched. |
| `name` | string | Template name. |
| `severity` | string | Template severity. |
| `matched_at` | string | What nuclei matched against. |
| `evidence_dir` | string | Output directory for the scan that found it. |
| `status` | string | Set to `new`. Change it by hand as you work through findings. |
| `first_seen` | date | When it was first recorded. |
| `client` | string | Copied from `takeover_scope`. |

Deleting a row means the finding will alert again the next time it is seen, which is a handy way to re-check something after it has been fixed.

## Importing the workflows

Import the Scan first, then the Monitor, which calls the Scan by its preserved workflow ID.

After importing, replace the placeholders:

| Placeholder | Replace with |
|---|---|
| `DATA_TABLE_takeover_scope`, `DATA_TABLE_takeover_findings` | Re-select the table in each data table node. |
| `CREDENTIAL_ID` | Re-link the **Discord Bot account** credential on both Discord nodes. |
| `DISCORD_GUILD_ID`, `DISCORD_ALERTS_CHANNEL_ID` | Re-select the server and channel on both Discord nodes. |
