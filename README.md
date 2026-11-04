# arturo_apitest

Standalone, **oracle-driven** API security harness for task-based verification
APIs. It consumes your Postman v2.1 collections as *structure* and runs
OWASP-API + ML-backend test suites. The design goal is **no false positives**:
nothing is reported unless it is confirmed by a differential, an out-of-band
callback, a reflected sentinel, or a reproduced stability gate.

Burp is used alongside it (Collaborator for OOB, Autorize if you prefer) by
flipping one proxy flag — every request then mirrors through Burp unchanged.
Requests go out with a rotating, realistic `User-Agent` (Chrome, Firefox,
Safari, Edge, Postman, mobile), never `python-httpx`.

## Why this shape

The brain is `engine/oracle.py`. Everything else feeds it. A candidate signal
that no oracle confirms is discarded, not reported:

| Confirmation | Used for | Rule |
|---|---|---|
| **Differential** | BOLA/BFLA (API1/3/5), broken auth (API2) | Flag only when tenant **B receives tenant A's exact content**, or an unauthenticated / mismatched-credential request returns the authenticated body. A 200 with different content is a clean pass. |
| **Out-of-band** | SSRF (API7), blind injection, file parsing (XXE) | Flag only on a **real callback** — a Collaborator/interactsh hit, or a hit on the built-in catcher server. No error-string or status-code guessing. |
| **Reflection** | mass assignment (API3), CORS, host-header, open redirect | Flag only when an injected sentinel / spoofed value is **echoed back** (a bound property, a reflected Origin/Host, a Location pointing at the attacker host). |
| **Stability gate** | any candidate probe | Must **reproduce N/N times**; flaky-once is discarded. |
| **Corpus label** | ML forgery/deepfake | Your **ground-truth label** is the oracle: flag when the backend accepts a `forged` sample or rejects a `genuine` one. |

The collection's own hardcoded `account-id`/`api-key` values are **never used**
as a test identity. They're reported as an API8 hygiene finding so you rotate
them.

## Suites

All eight run by default; select with `--suites a,b,c`. Each self-skips when its
prerequisites are missing.

| Suite | Class | Confirmed by | Needs |
|---|---|---|---|
| `authz` | BOLA/BFLA cross-tenant (API1/3/5) | differential | identities A **and** B |
| `broken_auth` | no-credential access, credential confusion (API2) | differential | identity A (B for confusion) |
| `injection` | SSRF + blind injection (API7) | OOB callback | identity A + `oob.domain` + `oob.hits_file` |
| `misconfig` | CORS reflection, TRACE/XST (API8) | reflection + gate | identity A |
| `bopla` | mass assignment (API3) | reflection + gate | identity A |
| `ml` | corpus forgery, prompt-injection flip, API4 abuse | corpus label + gate | identity A + corpus manifest |
| `file_upload` | unrestricted file / XXE / SSRF-via-file (API7/10) | catcher parse callback | identity A + reachable `upload.public_base` |
| `redirect_host` | open redirect, host-header injection | reflection + gate | identity A |

## Install

```bash
pip install -r requirements.txt    # httpx, pyyaml, pillow(optional)
```

## Configure

```bash
cp config/settings.example.yaml    config/settings.yaml
cp config/identities.example.yaml  config/identities.yaml   # two tenants, SECRET
cp config/overrides.example.yaml   config/overrides.yaml     # non-secret {{vars}}
```

**Environment variables** resolve in this order (later wins): Postman
environment export → `overrides.yaml` → `base_url`. You do **not** put
`account_id` / `api_key` anywhere — auth is injected per-identity.
Either export a Postman environment and point `postman_env:` at it, or just set
`base_url` in `overrides.yaml` by hand.

**Identities** — the authz suite needs two separate authorised tenants in
`identities.yaml` (`A` and `B`). Without them the authz suite skips itself.
`broken_auth` runs with only A, but its credential-confusion check also needs B.

**Burp / OOB** — set `proxy.enabled: true` and point `proxy.url` at your Burp
listener. TLS verify is off while proxying so Burp's CA works. The injection
suite confirms callbacks from a hits file: set `oob.domain` to your
Collaborator/interactsh host **and** `oob.hits_file` to a file your collaborator
client appends interactions to (e.g. `interactsh-client -o hits.txt`). Without
`oob.hits_file`, payloads still fire but cannot be confirmed, and the runner
says so rather than guessing. `engine/oracle.py` also exposes the `OOBProbe`
contract if you prefer to wire `was_hit()` to a live API directly.

**File-upload catcher** — `file_upload` hosts hostile SVG/XML/HTML at a URL the
backend fetches, and confirms only when the backend parses it and resolves an
embedded reference back to the catcher. The target must be able to reach the
catcher, so set `upload.public_base` to a routable URL (a VPS, an
ngrok/cloudflared tunnel, or a LAN address) and `upload.bind_port` to the local
port. Leave `public_base` blank to skip the suite.

## Run

```bash
# parse + plan only, no network — good first step:
python -m arturo_apitest.runner --config config/settings.yaml \
    --collections "collections/*.json" --out out --dry-run

# full run (all suites; each fires only if its prerequisites are met):
python -m arturo_apitest.runner --config config/settings.yaml \
    --collections "collections/*.json" --out out

# a subset:
python -m arturo_apitest.runner --config config/settings.yaml \
    --collections "collections/*.json" --suites authz,bopla,redirect_host --out out
```

Run it from the project root so `-m arturo_apitest.runner` resolves. Output:
`out/report.md` and `out/report.json`.

## Layout

```
arturo_apitest/
  engine/
    collection.py   Postman v2.1 parser -> RequestTemplate (tags injectable + doc-url fields, list-aware)
    envresolve.py   {{var}} resolution from Postman env + manual override
    config.py       settings + identities
    client.py       httpx client, Burp proxy, per-identity auth, rotating UA, sync/async+poll
    oracle.py       differential / OOB / reflection / stability + FileOOBProbe  (the FP killers)
    mutate.py       path-addressed body mutation
    payloads.py     SSRF / injection / prompt-injection / mass-assign / upload catalogues
    imageabuse.py   API4 resource-abuse image generator
    catcher.py      self-contained HTTP catcher for the file_upload suite
    report.py       dedupe + JSON/Markdown
  suites/
    authz.py          A/B request_id differential (BOLA/BFLA)
    broken_auth.py    no-credential access + credential confusion (API2)
    injection.py      OOB-confirmed SSRF + injection
    misconfig.py      CORS reflection + TRACE/XST (API8)
    mass_assignment.py reflection-confirmed BOPLA (API3)
    ml_image.py       corpus accuracy + prompt-injection flip + API4
    file_upload.py    unrestricted file / XXE / SSRF-via-file (catcher-confirmed)
    redirect_host.py  open redirect + host-header injection
  config/           *.example.yaml templates (real ones gitignored)
  collections/      your Postman exports (gitignored)
  corpus/           labelled genuine/forged samples + manifest.csv (gitignored)
  runner.py         CLI
```

## ML corpus

Copy `corpus/manifest.example.csv` to `corpus/manifest.csv` and fill in rows
with your ground truth (`label` = genuine|forged, `expect_pass` = should a
correct backend accept it). The `service` column must match an endpoint's
service path (e.g. `analyse/any_image`), and that endpoint needs a document-URL
sink. Samples can be local paths or https URLs the backend can fetch. The
`decision_reader` in `runner.py` maps the backend response to pass/fail — **tune
its keys to the real response schema** (it currently looks for `is_tampered`,
`verified`, `verification_status`, etc.). When it can't tell, it returns `None`
and the sample is skipped, never guessed.

## Scope / safety

Point this only at an environment you are authorised to test. A full run sends
real SSRF, injection, TRACE, extra-field, redirect, host-header, and hostile-file
requests to the target. The injection and SSRF suites refuse to run without a
configured OOB channel, and `file_upload` refuses without a reachable catcher —
they will not infer. Rate limits are in `settings.yaml` (`throughput`). This
harness is for your own authorised staging target.
