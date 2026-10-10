# Wazuh Triage

These workflows sit on top of a Wazuh indexer and turn its firehose of alerts into a short list of things a human should actually look at. **Alert Triage** handles high-severity Wazuh alerts, fingerprinting and deduplicating them before an LLM decides whether to escalate. **Honeypot Payload Analysis** does the same job for payloads captured by a web honeypot that ships its events into Wazuh. **Rewind To Last N** is a small utility for replaying recent alerts through triage after we change a prompt or a suppression rule.

All three query the indexer directly over its OpenSearch API, keep their polling cursors in an n8n data table, and post to Discord. The LLM calls go to a local Ollama instance, so no alert content leaves the network.

## What does each workflow do?

### Alert Triage

Runs every 5 minutes (and on demand with *Poll Now*). It reads its cursor from `wazuh_state`, then searches `wazuh-alerts-4.x-*` for anything at rule level 12 or above since the last poll. Rule groups in `vulnerability-detector` are excluded because they produce a constant stream of package findings that need a different workflow, although CVEs on the watchlist are still let through.

Each alert is normalised into a flat record and given a **fingerprint** made from rule ID, agent, source IP, user, file path, CVE and package, so repeats of the same event collapse together. The *Classify* step then works through every fingerprint in this order:

1. **Watchlist** hits from `wazuh_watch` always go to triage and always escalate, but repeats within 60 minutes are only recorded.
2. **Suppression rules** from `wazuh_suppress` record the alert as `suppressed` and stop there.
3. **Dedupe**: a fingerprint already triaged within 6 hours (24 hours if the last verdict was `noise`) reuses the previous verdict.
4. **Burst collapse**: when 8 or more distinct fingerprints fire on the same rule in one poll, only the worst one is triaged and the rest are recorded as `burst`.
5. A per-run cap of 15 triage calls, with level 15 alerts always triaged regardless.

External source IPs on alerts heading for triage are enriched through the **IP Threat Intel** sub-workflow in `../threat-intel` (AbuseIPDB, VirusTotal, GreyNoise and OTX), at most 4 lookups per run, with results cached from the last 24 hours of Postgres history.

The LLM returns a false-positive percentage, a verdict, a one-line summary and, for noise, a suggested narrow suppression. *Decide* combines that with hard rules: level 15 always escalates, a source IP with bad reputation escalates unless the model is very confident it is noise, and if Ollama is unreachable the workflow falls back to level and reputation alone rather than going quiet. Only `escalate` verdicts reach Discord. More than 5 escalations in one poll are rolled up into a single embed.

Every fingerprint is upserted into the Postgres `wazuh_alerts` table, rows older than 90 days are pruned, and the cursor is saved back to `wazuh_state`. A daily digest at 08:05 summarises the last 24 hours by verdict and lists the noisiest non-escalated rules along with any suppression hints, which is the main input for tuning.

### Honeypot Payload Analysis

Runs every 15 minutes. It reads `hp_cursor` from `wazuh_state` and pulls events from the `honeypot` rule group that carry something worth analysing: detections, a request body, decoded layers, artifacts or a query string.

Payloads are deduplicated by content (method, path, query, the non-boilerplate headers and body) into `honeypot_payloads`, so a scanner hitting the same exploit from 500 IPs is one row with a count and a list of source IPs. Static IOC extraction pulls URLs, IPs, shell commands and decodable base64 out of every layer before anything reaches the model.

Each payload is also given a **signature**, a normalised shape of the request with IPs, numbers, UUIDs, JWTs, timestamps, base64 blobs and out-of-band callback domains replaced by tokens. Variants of the same exploit share a signature, and a new payload whose signature has already been analysed inherits that analysis instead of costing another LLM call. Inheritance only happens when every indicator in the new payload is already known and the analysed sibling was either alerted or scored below 40, so anything carrying fresh infrastructure still gets a proper look.

Up to 8 unanalysed payloads per run, heaviest first, go to the LLM, which returns technique, target, CVEs, stage, malware family, a deobfuscated core, IOCs, an interest score from 0 to 100 and a detection idea. A payload alerts when it was seen in the last 6 hours and either scores 60 or more, carries a real callback URL or command, or is classified as a dropper, C2 or persistence stage. Alerts are then suppressed if the signature was already alerted in the last 30 days and nothing in it is new, so we only hear about a known exploit again when it starts pointing at fresh infrastructure.

The Postgres tables are created by the workflow itself on every run (`CREATE TABLE IF NOT EXISTS`), so there is nothing to set up beyond the database.

The workflow expects honeypot events in Wazuh with this shape under `data`: `http.method`, `http.path`, `http.query`, `http.headers` (a list of `{name, value}`), `body`, `src_ip`, `sensor_host`, `detections` (a list of `{id, name, severity, location, evidence, cves}`), `decoded_layers`, `artifacts` and `categories`. Any honeypot that logs JSON in that shape and is decoded into the `honeypot` rule group will work.

### Rewind To Last N

A manual utility. It finds the last N (default 20, set in *Build Query*) level 12+ alerts outside `vulnerability-detector` and rewinds the Alert Triage cursor to the oldest of them with a `force` flag. The next poll re-processes all of them and bypasses the dedupe and watchlist repeat windows, which is how we test a prompt change against real alerts.

## Creating the data tables

Create these under **Overview > Data tables** in n8n before importing. The names must match exactly, and the column types matter because the workflows compare booleans and dates directly.

### `wazuh_state`

Key-value store for polling cursors. Used by all three workflows. The workflows create their own rows (`cursor` for Alert Triage, `hp_cursor` for Honeypot Payload Analysis) on first run.

| Column | Type |
|---|---|
| `key` | string |
| `value` | string |

### `wazuh_suppress`

Suppression rules for Alert Triage. A matching alert is recorded as `suppressed` and never triaged or posted. The daily digest's suppression hints are written in a form that maps onto these columns.

| Column | Type | Meaning |
|---|---|---|
| `enabled` | boolean | Only `true` rows apply. |
| `rule_id` | string | Wazuh rule ID, or several separated by commas. |
| `agent` | string | Agent name, case-insensitive. |
| `field` | string | A normalised alert field to test, such as `srcip`, `user`, `path`, `log` or `description`. |
| `pattern` | string | Case-insensitive regex tested against `field`. |
| `reason` | string | Shown as the recorded reason. |
| `expires` | date | Optional. The rule stops applying after this date. |

A row needs at least `rule_id` or `agent`. When `field` and `pattern` are set as well, all of them must match, so keep rules as narrow as possible.

### `wazuh_watch`

Watchlist for Alert Triage. Anything matching an active row is fetched regardless of rule level, always triaged and always escalated.

| Column | Type | Meaning |
|---|---|---|
| `enabled` | boolean | Only `true` rows apply. |
| `type` | string | `cve`, `detection_id`, `rule_id` or `field`. |
| `value` | string | The CVE, detection ID or rule ID to match exactly, or a regex when `type` is `field`. |
| `field` | string | Only for `type = field`: the normalised alert field to test. |
| `reason` | string | Shown in the Discord alert. |
| `expires` | date | Optional. |

`detection_id` matches the `data.detections.id` values that the honeypot attaches to its events, which is how we get paged on a specific exploit even when its Wazuh rule level is low.

## Creating the Postgres tables

These workflows use a PostgreSQL database for the larger state (see the `postgres` role in this repo), connected through an n8n **Postgres** credential.

The `honeypot_*` tables are created by the *Ensure Schema* node in Honeypot Payload Analysis. `wazuh_alerts` has to be created by hand before Alert Triage first runs:

```sql
CREATE TABLE wazuh_alerts (
    fingerprint text PRIMARY KEY,
    rule_id text,
    level integer,
    description text,
    agent text,
    srcip text,
    "user" text,
    groups text,
    first_seen timestamptz,
    last_seen timestamptz,
    count integer NOT NULL DEFAULT 0,
    verdict text,
    reason text,
    fp_percent integer,
    summary text,
    intel text,
    suppress_hint text,
    notified boolean NOT NULL DEFAULT false,
    sample_id text
);
CREATE INDEX wazuh_alerts_last_seen_idx ON wazuh_alerts (last_seen);
CREATE INDEX wazuh_alerts_rule_idx ON wazuh_alerts (rule_id);
CREATE INDEX wazuh_alerts_srcip_idx ON wazuh_alerts (srcip);
CREATE INDEX wazuh_alerts_verdict_idx ON wazuh_alerts (verdict);
```

`verdict` is one of `escalate`, `monitor`, `noise`, `burst`, `suppressed` or `untriaged`. `intel` holds the cached reputation JSON for the source IP, so repeat offenders do not cost another round of API calls.

For reference, the honeypot tables the workflow creates are:

| Table | Key | Holds |
|---|---|---|
| `honeypot_payloads` | `payload_hash` (md5 of the canonical request) | One row per distinct payload: request parts, detections, static IOCs, weight, count, source IPs, sensors, LLM `analysis` (jsonb), `interest`, `sig_hash` and `ioc_keys`. |
| `honeypot_signatures` | `sig_hash` | One row per request shape: variant and event counts, the sample payload, technique and alert history used for re-alert suppression. |
| `honeypot_iocs` | `ioc` (`ip:`, `dom:` or `det:` prefixed) | Every indicator seen, how many payloads carried it and when it was first alerted, which is what makes "known signature, new indicators" alerts possible. |

## Importing the workflows

Import **IP Threat Intel** from `../threat-intel` first, because Alert Triage calls it by ID. Then import the three workflows here. Workflow IDs are preserved on import, so the sub-workflow call and the `errorWorkflow` setting on Alert Triage and Honeypot Payload Analysis (which points at the ASM Error Handler in `../asm-pipeline`) resolve without editing. Import that Error Handler too, or clear the setting.

After importing, replace the placeholders:

| Placeholder | Where | Replace with |
|---|---|---|
| `WAZUH_INDEXER` | *Search* HTTP nodes | Hostname or IP of the Wazuh indexer. The nodes accept self-signed certificates. |
| `OLLAMA_HOST` | *LLM Triage*, *LLM Analyse* | Hostname or IP of the Ollama server. |
| `OLLAMA_MODEL` | *Attach Intel*, *Build Prompt*, *Parse Analysis* | An Ollama model that follows JSON output reliably. A 7 to 14B instruct model is enough. |
| `DATA_TABLE_*` | Data table nodes | Re-select the matching table in each node. |
| `CREDENTIAL_ID` | HTTP, Postgres and Discord nodes | Re-link the credentials listed below. |
| `DISCORD_GUILD_ID`, `DISCORD_ALERTS_CHANNEL_ID`, `DISCORD_HONEYPOT_CHANNEL_ID` | Discord nodes | Re-select the server and channels. |

Credentials used in this folder:

| Name | Type | Used for |
|---|---|---|
| Wazuh Opensearch | HTTP Basic Auth | Indexer search, read-only user is enough. |
| Postgres account | Postgres | `wazuh_alerts` and the `honeypot_*` tables. |
| Discord Bot account | Discord Bot | Alerts and digests. |
