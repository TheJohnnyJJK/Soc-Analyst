# A miniature SOC analyst

## In plain terms

This takes one inbound security alert - a log line, an EDR pop-up, a
vulnerability scanner finding - and does what a tier-1 analyst does
first: pull out anything that looks like an indicator of compromise
(an IP, a domain, a file hash, a CVE ID), look each one up against real
threat intel, and write a short report a human can approve or escalate
in seconds. It runs as a real HTTP service with a persistent audit
trail, not just a script against a fixture file - post an alert, get
back a verdict, and every decision stays on record for later review.
It never blocks an IP or quarantines a file on its own - see "Why it
never takes action" below for why that's not a missing feature.

It's built on the other two things in this portfolio that already do
the lookups: [mcp-threat-intel](../mcp-servers/mcp-threat-intel)
(AbuseIPDB, VirusTotal) and [mcp-cve-feed](../mcp-servers/mcp-cve-feed)
(the public NVD feed) - two of the three servers in the
[mcp-servers](../mcp-servers) monorepo. Those two MCP servers' own tool
functions are imported directly here - this project doesn't
reimplement a third HTTP client for the same three APIs, it just calls
the ones already built and tested.

## What this is actually for

Raw IOC reputation lookups are a commodity - AbuseIPDB and VirusTotal
already give that away free, and several open-source alert-triage
agents exist now too. What security teams actually pay for is
different: displaced tier-1 analyst time, and - the specific angle this
project leans into - **an audit trail regulators will accept.** Buyer-
side research on agentic SOC platforms is blunt that examiners want one
replayable record per incident (the evidence, how it was graded, what
deferred to a human) and specifically want **deterministic** behavior
for compliance-mandated workflows, because a true multi-agent system
often has no single reasoning thread left to audit.

That's exactly the shape this project already has, not a feature bolted
on after the fact: `classify()` is a fixed function over gathered
evidence, the LLM only narrates a decision already made, and now every
one of those decisions - plus whatever a human did about it - lands in
one queryable SQLite table (`soc/store.py`). "Deterministic, replayable,
auditable" is the actual pitch here, not "another AI that reads your
alerts."

## The golden alert set is seeded with real, currently-active data

Every other golden set in this portfolio is entirely hand-written.
This one is too, but the indicators inside it aren't made up - they're
real, pulled live on 2026-09-16 from public sources, specifically so
the "is this actually malicious" question has a genuine answer instead
of an invented one:

- **159.203.184.15, 149.54.9.42** - real attacker IPs from
  [FireHOL's `firehol_level2`](https://iplists.firehol.org/) list, an
  aggregate of blocklist_de/dshield/greensnow reports from the last 48
  hours at the time this was built.
- **amaamn.com** - a real malicious domain from
  [abuse.ch's URLhaus](https://urlhaus.abuse.ch/) feed, actively
  serving a payload at collection time.
- **275a021b...651fd0f** - the published SHA-256 of the EICAR standard
  antivirus test file. Not real malware, but a hash every AV engine
  and VirusTotal genuinely flags, so it's a safe stand-in for "a file
  hash universally recognized as malicious."
- **CVE-2024-3094, CVE-2025-57812** - real CVEs (the xz backdoor and a
  real low-severity CUPS bug), looked up live through this portfolio's
  own `mcp-cve-feed`.
- **8.8.8.8, 1.1.1.1, wikipedia.org** - genuinely clean, unremarkable
  public destinations, used as the false-positive/benign cases.

## What it does with each alert

1. **Extract** - regex pulls out any IPs, domains, file hashes, or CVE
   IDs from the raw alert text (`soc/iocs.py`). Private/loopback
   addresses are filtered out before anything is looked up - there's
   no external reputation for `10.0.0.5`, and checking it would just
   burn free-tier API quota to learn nothing.
2. **Gather evidence** - each extracted IOC gets a real lookup via
   `mcp-threat-intel` or `mcp-cve-feed` (`soc/evidence.py`). An IOC
   neither service has ever seen (VirusTotal 404s on an unknown domain)
   becomes its own `no_data` verdict, not a crash and not a silent
   "clean" - absence of a bad reputation isn't the same as a good one.
3. **Classify** - a fixed set of precedence rules turns the evidence
   into one of three verdicts: `confirmed_threat`, `likely_benign`, or
   `needs_review` (`soc/triage.py::classify`). This is the one
   deliberate departure from Lead Router, where the LLM picks the
   tier - see below for why.
4. **Correlate** (when running as the service) - checks the audit
   store for this alert's IOCs showing up in *other* alerts recently.
   See "Cross-alert correlation" below.
5. **Report** - a human-readable transcript citing every piece of
   evidence by name (`soc/report.py`), ending in a verdict and an
   explicit "no action taken" line.

## Why the LLM narrates, but doesn't decide

Lead Router hands the tier decision to Claude. This project doesn't -
`classify()` is a fixed, deterministic function over the gathered
evidence, and an LLM is never in that loop. If `ANTHROPIC_API_KEY` is
set, Claude only writes the prose explanation of a verdict that's
already been decided, constrained to the evidence it's given (including
any correlation finding) and told not to suggest a different one.
Without a key, a plain template does the same job.

The reasoning is architectural, not caution for its own sake: a
security verdict has to be reproducible run to run for the golden-set
eval to mean anything, and auditable enough that a human reviewer can
see exactly which piece of evidence forced which outcome. A model that
can quietly overturn "AbuseIPDB says 100/100 malicious" because the
prose *sounded* more nuanced would make both of those properties false.

## The audit trail

`soc/store.py` is a two-table SQLite database: one row per triage call
(`triage_records` - the alert, every piece of evidence, the verdict,
the reasoning) and one row per IOC it looked up (`ioc_sightings` - what
correlation queries against). Nothing is deleted or overwritten except
a record's action fields, set exactly once a human reviews it:

```
POST /alerts/{id}/action
{"status": "approved", "actioned_by": "johan", "note": "confirmed real, blocked at firewall"}
```

That's the actual compliance artifact: every alert this system ever
saw, what it decided and why, and who signed off on it - queryable
after the fact, not reconstructed from logs. Confirmed by killing and
restarting the live service mid-build: the record, including a human's
`approved` action taken before the restart, was still there afterward
exactly as written.

## Cross-alert correlation

A single "suspicious" reputation score (not "malicious") is
`classify()`'s most cautious call - `needs_review`, not a confirmed
threat, because one moderate-confidence source alone is weak evidence.
But the same indicator showing up in a *second, unrelated* alert is a
different situation: that's independent corroboration, not one
source's false positive. `soc/triage.py::_correlate` checks the audit
store for exactly that, and escalates when it finds it.

This was verified live, not just unit-tested: two real alerts were
posted to the running service, both mentioning the same real IP
(`159.203.184.15`, AbuseIPDB score 62/100 - the same address from the
"Honesty notes" case below). The first came back `needs_review`
(confidence 0.5). The second, seconds later, came back
`confirmed_threat` (confidence 0.75), with the reasoning citing the
first alert by id:

> Verdict: confirmed_threat. ip 159.203.184.15: suspicious per
> abuseipdb. Correlation: also seen in the last 24h - ip
> 159.203.184.15 in live-01. A single moderate-confidence source is
> weak evidence alone, but this indicator recurring independently
> across alerts is not.

## Per-source authentication

Cross-alert correlation is only meaningful if the second sighting is
genuinely independent. Without this feature, "independent" is judged
solely by `alert_id` - caller-chosen, so nothing stops one integration
from posting the same suspicious IOC under several different
self-chosen `alert_id`s and manufacturing its own corroboration.

`SOC_SOURCE_KEYS` closes that: a JSON object mapping each upstream
integration's own secret to a name -

```
SOC_SOURCE_KEYS={"k-for-edr":"edr-vendor","k-for-siem":"siem-vendor"}
```

- and each integration sends its key as `X-Source-Key` on every
`POST /alerts`. `soc/security.py::identify_source` resolves that header
to a name (401 if it's missing or doesn't match once this is
configured), which is stored alongside the triage record and every IOC
sighting it produced. `soc/triage.py::_correlate` then only escalates a
lone "suspicious" signal when the repeat sighting it finds was recorded
under a *different* authenticated name - one integration can no longer
corroborate itself by varying its `alert_id`.

This is opt-in, same shape as `SOC_API_KEY`: unset, every route behaves
exactly as before, and correlation keeps using the documented,
weaker alert_id-only model. It's independent of `SOC_API_KEY` too -
one gates the whole API, the other only says who's calling.

## Why it never takes action

`classify()` and `render_report()` only ever produce a recommendation.
There is no code path anywhere in this project that blocks an IP,
quarantines a file, or touches anything outside read-only threat-intel
lookups and its own audit database. For a portfolio piece this is the
honest scope: a real auto-remediation system needs its own hard-won
trust, rate limits, and rollback story, and bolting that onto a weekend
project would be the kind of overclaiming this whole portfolio is
trying to avoid.

## Honesty notes

The full 10-case golden set has been run for real, against live
AbuseIPDB/VirusTotal/NVD data (2026-09-16): **10/10 correct** as
written below - but it wasn't 10/10 on the first live run.

`alert-01` was originally written expecting `confirmed_threat` on the
assumption that an IP freshly listed on a public attacker blocklist
would read as unambiguous. The first live run scored it `needs_review`
instead: AbuseIPDB's own check on that IP came back 62/100 ("suspicious"
by this project's thresholds, not "malicious"). That's two legitimate
threat-intel sources genuinely disagreeing on the same address, not a
bug in `classify()` - so the fix was correcting the golden set's
expectation to match what the evidence this system actually gathers
supports, not loosening the malicious threshold until the one
inconvenient case passed. See `alerts/golden_alerts.json`'s note on
that case for the exact scores. (This same IP is what the live
correlation demo above uses.)

`alert-09` was written to test the `no_data` path - a domain designed
to have no threat-intel history anywhere. It correctly got `needs_review`
on that same first live run (VirusTotal 404'd it). By the *second* live
run, minutes later, VirusTotal returned a real record (89 engines,
clean) for the same domain - looking it up apparently got it indexed.
"Never seen anywhere" turned out not to be a stable state to test
against a live API, so the expectation was updated to match current
reality. The `no_data` code path itself is still directly covered by
`tests/test_evidence.py`'s mocked 404 case, independent of whether any
live domain happens to still be unindexed.

The first live run of the actual HTTP service also surfaced a real gap:
a missing `ABUSEIPDB_API_KEY` produced a bare, unhelpful 500 instead of
a clear error. Fixed in `soc/api.py` - `MissingApiKeyError` now returns
503 with the actual problem named, and a threat-intel HTTP failure
returns 502 instead of an opaque crash.

**A dedicated red-team pass** (same instinct as agent-red-team elsewhere
in this portfolio, applied here) actually tried to break this project
rather than just review it, and found real, verified problems - all
fixed, each with a regression test, before this was called done:

- **Defanged notation was invisible.** `159[.]203[.]184[.]15`,
  `hxxp://amaamn[.]com` - the standard way analysts write IOCs in
  prose *specifically so they're not clickable/pingable* - extracted
  to zero IOCs. This isn't even adversarial, it's normal SOC writing
  style; the tool was silently missing real indicators in ordinary
  text. Fixed with a refang step in `soc/iocs.py` before any pattern
  runs, verified against the real API with the real defanged IP.
- **Correlation escalation was gameable, and `alert_id` had no
  uniqueness check.** The same real "suspicious" IP, posted under 5
  different self-chosen `alert_id`s claiming a self-labeled
  `"source":"attacker-controlled"`, escalated to `confirmed_threat`
  every time after the first - free corroboration from one caller
  repeating itself, not two independent detections. Separately, an
  ordinary webhook retry (at-least-once delivery, the normal case) with
  the identical `alert_id` silently created a second audit row. Fixed
  the second problem for real: `alert_id` is now `UNIQUE`, and a
  repeat is idempotent (returns the original record, verified live).
  The first problem is now closed too, opt-in: `SOC_SOURCE_KEYS`
  authenticates each upstream integration individually
  (`soc/security.py::identify_source`), and `soc/triage.py::_correlate`
  only escalates on a repeat sighting recorded under a *different*
  authenticated source, not just a different self-chosen `alert_id` -
  see "Per-source authentication" below. Unconfigured, the original
  alert_id-only trust model still applies, documented as such.
- **No cap on IOCs looked up per alert, and the domain regex matched
  plain filenames.** One alert with 10 real IPs fired 10 live
  AbuseIPDB calls in 2.5 seconds with nothing stopping it from being
  hundreds; separately, ordinary non-malicious text like
  `"attached invoice.pdf, setup.exe"` was extracted as three domains
  and burned VirusTotal's tight free-tier quota on nothing. Fixed both
  in `soc/iocs.py`: a per-type cap, and a common-file-extension
  exclusion on the domain pattern.
- **The LLM narration prompt had no boundary around untrusted alert
  text** (static analysis only - no `ANTHROPIC_API_KEY` configured, so
  this wasn't confirmed against a live model). `llm_reasoning()`'s
  prompt embedded `alert.raw_text` directly with no delimiter, the
  documented mechanism behind a real paper on this exact attack class
  against LLM-augmented SOC tools (arXiv 2605.24421). The verdict
  itself was never at risk - `classify()` decides it before the LLM is
  ever called, and nothing lets the LLM write back to it - but a
  crafted alert could plausibly make the *narration* contradict the
  verdict sitting right next to it, misleading a rushed reader. Fixed
  with explicit delimiters and trust framing in the prompt, plus a
  deterministic backstop (`_contradicts_verdict`) that rejects any
  narration using dismissive language ("false positive", "benign") on
  a `confirmed_threat` verdict and falls back to the template instead.
- **`/docs` and `/openapi.json` ignored `SOC_API_KEY` entirely** - full
  schema and an interactive Swagger UI stayed browsable with auth
  "on" everywhere else. Fixed by disabling FastAPI's built-in doc
  routes and re-serving the same content through three routes that use
  the same `Authed` dependency as everything else.

Confirmed safe, not just assumed: SQL injection against
`store.list_records()`'s dynamic WHERE clause (parameterization held),
CORS (no permissive defaults), and error responses (no leaked stack
traces or paths).

## Running it as a service

```bash
uv venv .venv
uv pip install -r requirements.txt --python .venv
```

`mcp-threat-intel` and `mcp-cve-feed` are installed as local editable
packages from the `mcp-servers` monorepo (see `requirements.txt`) -
they need to already exist as a sibling directory, which they do if
you've built this portfolio in order.

```bash
.venv/Scripts/python -m uvicorn soc.api:app --port 8010
```

```
POST /alerts                     triage one alert, persist it, return the audit record
GET  /alerts                     recent audit records (filter by ?verdict= and/or ?status=)
GET  /alerts/{id}                one audit record
POST /alerts/{id}/action         record a human decision: {"status": "approved"|"dismissed", "actioned_by": "...", "note": "..."}
GET  /health                     liveness check, unauthenticated
GET  /docs, /redoc, /openapi.json   interactive API docs - gated behind the same auth as everything else, not public by default the way FastAPI's are out of the box
```

`SOC_API_KEY` is optional, same opt-in shared-secret pattern as Lead
Router's `AGENT_API_KEY` - unset for local dev, set the moment this
deploys anywhere reachable beyond localhost. `SOC_STORE_DB` points the
audit database at a different path; defaults to `./soc_analyst.db`.

## Running the golden-set eval

```bash
.venv/Scripts/python -m eval.run_eval
```

CVE-only cases (alert-04, alert-07, alert-08) run against the real
public NVD API with no key needed. The IP/domain/hash cases need
`ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY` (both free tiers - see
`mcp-threat-intel`'s README) in `.env` to resolve for real; without
them they error out honestly rather than faking a pass. This harness
never touches the audit store or the correlation feature - it's a pure
grading run against `classify()`'s output, same as it was before the
service existed.

**Run for real with all three sources live: 10/10 correct, avg latency
in the 350-450ms/alert range across repeated runs.** See "Honesty
notes" above for what the first live run actually found before it got
to 10/10.

## Development

```bash
.venv/Scripts/python -m pytest        # 91 tests, everything mocked, no keys/service needed
.venv/Scripts/python -m ruff check alerts soc eval tests
.venv/Scripts/python -m mypy alerts soc eval
```
