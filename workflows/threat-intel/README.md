# Threat Intel

Reputation lookups for IP addresses, split into a reusable sub-workflow and a small form on top of it. **IP Threat Intel** asks four free intelligence sources about one IP and returns their raw answers together, and **Threat Intel** is a form that accepts an IP or a domain and builds an HTML report from those answers. Alert Triage in `../wazuh-triage` also calls IP Threat Intel to enrich source IPs before the LLM sees them, which is the main reason it lives in its own workflow.

## What does each workflow do?

### IP Threat Intel

A sub-workflow with one input, `ipAddress`. It queries these four sources in parallel and merges the four responses into its output unchanged, leaving interpretation to the caller:

| Source | Endpoint | What it adds |
|---|---|---|
| AbuseIPDB | `/api/v2/check` | Abuse confidence score, report count, ISP, country, usage type, Tor flag. |
| VirusTotal | `/api/v3/ip_addresses/<ip>` | Engine verdict counts, reputation, AS owner, tags. |
| GreyNoise Community | `/v3/community/<ip>` | Whether the IP is a known internet scanner, RIOT (known benign service) flag, classification. GreyNoise returns 404 for IPs it has never seen, which callers should treat as "not observed" rather than an error. |
| AlienVault OTX | `/api/v1/indicators/IPv4/<ip>` | Pulse count and validation notes. |

Free tiers are rate limited (VirusTotal especially), so callers should cache. Alert Triage caps itself at 4 lookups per run and reuses results from the last 24 hours.

### Threat Intel

A form with a single field, **IP Address or Domain**. An IP goes straight to IP Threat Intel. A domain is resolved to its A records through Google's DNS-over-HTTPS API and each resulting IP is looked up in turn. Once every IP has been checked, the *HTML* node renders the combined results as a styled report.

The form responds as soon as it is submitted, so the report is read from the *HTML* node's output in the execution view. Switching the form trigger to respond from a final **Respond to Webhook** or **Form** ending node would show it in the browser instead.

## Creating the credentials

Neither workflow uses data tables or Postgres. All four sources authenticate with an API key in a request header, so each one is an n8n **Header Auth** credential of type `httpMultipleHeadersAuth`:

| Credential name | Header |
|---|---|
| IP Abuse DB | `Key: <AbuseIPDB API key>` and `Accept: application/json` |
| VT API Key | `x-apikey: <VirusTotal API key>` |
| Greynoise API | `key: <GreyNoise API key>` |
| OTX API Key | `X-OTX-API-KEY: <OTX API key>` |

All four offer free keys that are enough for interactive use and light enrichment.

## Importing the workflows

Import **IP Threat Intel** first. Threat Intel and the Wazuh Alert Triage workflow call it by its workflow ID, which is preserved on import. Then re-link the four credentials above wherever a node shows `CREDENTIAL_ID`.
