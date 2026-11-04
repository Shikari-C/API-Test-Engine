# arturo_apitest

Standalone, **oracle-driven** API security harness for task-based verification
APIs. It consumes your Postman v2.1 collections as *structure* and runs
OWASP-API + ML-backend test suites. The design goal is **no false positives**:
nothing is reported unless it is confirmed by a differential, an out-of-band
callback, or a reproduced stability gate.

Burp is used alongside it (Collaborator for OOB, Autorize if you prefer) by
flipping one proxy flag — every request then mirrors through Burp unchanged.

## Why this shape

The brain is `engine/oracle.py`. Everything else feeds it:

| Confirmation | Used for | Rule |
|---|---|---|
| **Differential** | BOLA/BFLA/BOPLA (API1/3/5) | Flag only when tenant **B receives tenant A's exact content**. A 200 with different content is a clean pass. |
| **Out-of-band** | SSRF (API7), injection | Flag only on a **real Collaborator/interactsh callback**. No error-string or status-code guessing. |
| **Stability gate** | any candidate probe | Must **reproduce N/N times**; flaky-once is discarded. |
| **Corpus label** | ML forgery/deepfake | Your **ground-truth label** is the oracle: flag when the backend accepts a `forged` sample or rejects a `genuine` one. |

The collection's own hardcoded `account-id`/`api-key` values are **never used**
as a test identity. They're reported as an API8 hygiene finding so you rotate
them (your exports currently leak 216 such values across 73 endpoints).

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

**Burp** — set `proxy.enabled: true` and point `proxy.url` at your Burp listener.
TLS verify is off while proxying so Burp's CA works. Collaborator is wired by
setting `oob.domain` and implementing `OOBProbe.was_hit()` against its API
(`engine/oracle.py` has the stub + contract).

## Run

```bash
# parse + plan only, no network — good first step:
python -m arturo_apitest.runner --config config/settings.yaml \
    --collections "collections/*.json" --suites authz,injection,ml --out out --dry-run

# full run (fires only the suites whose prerequisites are met):
python -m arturo_apitest.runner --config config/settings.yaml \
    --collections "collections/*.json" --suites authz,injection,ml --out out
```

Output: `out/report.md` and `out/report.json`.

## Layout

```
arturo_apitest/
  engine/
    collection.py   Postman v2.1 parser -> RequestTemplate (tags injectable + doc-url fields)
    envresolve.py   {{var}} resolution from Postman env + manual override
    config.py       settings + identities
    client.py       httpx client, Burp proxy, per-identity auth, sync/async+poll
    oracle.py       differential / OOB / stability  (the FP killers)
    mutate.py       path-addressed body mutation
    payloads.py     SSRF / injection / prompt-injection catalogues
    imageabuse.py   API4 resource-abuse image generator
    report.py       dedupe + JSON/Markdown
  suites/
    authz.py        A/B request_id differential (BOLA/BFLA)
    injection.py    OOB-confirmed SSRF + injection
    ml_image.py     corpus accuracy + prompt-injection flip + API4
  config/           *.example.yaml templates (real ones gitignored)
  collections/      your Postman exports (gitignored)
  corpus/           labelled genuine/forged samples + manifest.csv (gitignored)
  runner.py         CLI
```

## ML corpus

Copy `corpus/manifest.example.csv` to `corpus/manifest.csv` and fill in rows
with your ground truth (`label` = genuine|forged, `expect_pass` = should a
correct backend accept it). Samples can be local paths or https URLs the
backend can fetch. The `decision_reader` in `runner.py` maps the backend
response to pass/fail — **tune its keys to the real response schema** (it
currently looks for `is_tampered`, `verified`, `verification_status`, etc.).
When it can't tell, it returns `None` and the sample is skipped, never guessed.

## Scope / safety

Point this only at an environment you are authorised to test. Injection and SSRF
suites refuse to run without a configured OOB channel (they will not infer).
Rate limits are in `settings.yaml` (`throughput`). This harness is for your own
authorised staging target.
```
