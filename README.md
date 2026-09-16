# A miniature SOC analyst

## In plain terms

This takes one inbound security alert - a log line, an EDR pop-up, a
vulnerability scanner finding - and does what a tier-1 analyst does
first: pull out anything that looks like an indicator of compromise
(an IP, a domain, a file hash, a CVE ID), look each one up against real
threat intel, and write a short report a human can approve or escalate
in seconds. It never blocks an IP or quarantines a file on its own -
see "Why it never takes action" below for why that's not a missing
feature.

It's built on the other two things in this portfolio that already do
the lookups: [mcp-threat-intel](../mcp-threat-intel) (AbuseIPDB,
VirusTotal) and [mcp-cve-feed](../mcp-cve-feed) (the public NVD feed).
Those two MCP servers' own tool functions are imported directly here -
this project doesn't reimplement a third HTTP client for the same
three APIs, it just calls the ones already built and tested.

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
4. **Report** - a human-readable transcript citing every piece of
   evidence by name (`soc/report.py`), ending in a verdict and an
   explicit "no action taken" line.

## Why the LLM narrates, but doesn't decide

Lead Router hands the tier decision to Claude. This project doesn't -
`classify()` is a fixed, deterministic function over the gathered
evidence, and an LLM is never in that loop. If `ANTHROPIC_API_KEY` is
set, Claude only writes the prose explanation of a verdict that's
already been decided, constrained to the evidence it's given and told
not to suggest a different one. Without a key, a plain template does
the same job.

The reasoning is architectural, not caution for its own sake: a
security verdict has to be reproducible run to run for the golden-set
eval to mean anything, and auditable enough that a human reviewer can
see exactly which piece of evidence forced which outcome. A model that
can quietly overturn "AbuseIPDB says 100/100 malicious" because the
prose *sounded* more nuanced would make both of those properties false.

## Why it never takes action

`classify()` and `render_report()` only ever produce a recommendation.
There is no code path anywhere in this project that blocks an IP,
quarantines a file, or touches anything outside read-only threat-intel
lookups. For a portfolio piece this is the honest scope: a real
auto-remediation system needs its own hard-won trust, rate limits, and
rollback story, and bolting that onto a weekend project would be the
kind of overclaiming this whole portfolio is trying to avoid.

## Running it

```bash
uv venv .venv
uv pip install -r requirements.txt --python .venv
```

`mcp-threat-intel` and `mcp-cve-feed` are installed as local editable
packages (see `requirements.txt`) - they need to already exist as
sibling directories, which they do if you've built this portfolio in
order.

```bash
.venv/Scripts/python -m eval.run_eval
```

CVE-only cases (alert-04, alert-07, alert-08) run against the real
public NVD API with no key needed - confirmed live during the build:
all three came back with the expected verdict. The IP/domain/hash
cases need `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY` (both free
tiers - see `mcp-threat-intel`'s README) in `.env` to resolve for real;
without them they error out honestly rather than faking a pass. The
full 10-case live run, and the time-to-triage number that's supposed to
be this project's proof deliverable, is left for a run with real keys
rather than faked here - see this portfolio's established pattern for
paid/keyed runs.

## Development

```bash
.venv/Scripts/python -m pytest        # 36 tests, everything mocked, no keys needed
.venv/Scripts/python -m ruff check alerts soc eval tests
.venv/Scripts/python -m mypy alerts soc eval
```
