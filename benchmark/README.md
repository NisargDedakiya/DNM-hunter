# Vulnerability-detection benchmark

Turns *"can NisargHunter AI find P3+ vulnerabilities?"* into a **measured recall
number** by scanning the bundled, deliberately-vulnerable [`guinea_pigs/`](../guinea_pigs)
targets and scoring the findings against a documented ground-truth catalog.

- [`ground_truth.yaml`](ground_truth.yaml) — every documented planted vuln in the
  guinea pigs, tagged with its Bugcrowd P-tier (P1 critical → P5 info). Sourced
  from each target's own README; nothing invented.
- [`score.py`](score.py) — scores a scan's findings: recall overall, **per
  P-tier (with an explicit P3+ number)**, per target, and the exact list of misses.
- `tests/` — unit tests for the scorer.

The scorer's own logic is verifiable without a live scan:

```bash
python benchmark/score.py --self-test
python -m unittest benchmark.tests.test_score -v
```

## Why this exists

Static/rule-based classes (IaC misconfig, secret regex, headers) are already
measurable in-process. The *engine-driven* classes — SQLi, RCE, IDOR, SSRF, the
CVE containers — need the full Docker stack + an LLM key + a live target, so
they can only be measured end-to-end. This harness is that measurement, ready to
run the moment the environment is up.

## Running the full benchmark

### 1. Bring up the platform
```bash
docker compose up -d --build        # webapp, agent, recon_orchestrator, Neo4j, Postgres, kali-sandbox
```
Set an LLM provider key in the app (Settings → AI Providers) — the AI planner,
attack skills, and validator need it.

### 2. Bring up a guinea pig (local, trusted host only)
```bash
cd guinea_pigs/dvws-node          && docker compose up -d --build   # 35 vulns + CVE containers
# or: guinea_pigs/node_serialize_1.0.0, guinea_pigs/apache_2.4.49,
#     guinea_pigs/apache_2.4.25, guinea_pigs/web-cache-poisoning
```
Attach it to the platform network so the scan containers can reach it by name:
```bash
docker network connect nisarghunter-network <guinea-pig-container>
```
> ⚠️ These targets are intentionally vulnerable. Never expose their ports to an
> untrusted network. (A public, NisargHunter-AI-authorized instance is also
> documented at `guinea_pigs/dvws-node/README.md`.)

### 3. Run a scan
Create a program/project targeting the guinea pig, enable the relevant modules
(for DVWS: recon + nuclei + the injection/IDOR/SSRF attack skills + GraphQL +
VHost/SNI), approve the AI recon plan, and let it run to completion. Findings
flow through the AI validator into remediations.

### 4. Export findings to the scorer's JSON contract
Findings live in Neo4j (`Vulnerability` nodes) and Postgres (`Remediation` rows).
Export either into a JSON array — field names are matched leniently.

From the webapp remediations API (per project):
```bash
curl -s "http://localhost:3000/api/remediations?projectId=<id>" \
  | jq '[.[] | {target:"dvws-node", category:.category, title:.title,
                severity:.severity, endpoint:(.affectedAssets[0].url // "")}]' \
  > findings.json
```

Or from Neo4j:
```cypher
MATCH (v:Vulnerability {user_id:$uid, project_id:$pid})
RETURN v.category AS category, v.title AS title, v.severity AS severity,
       coalesce(v.endpoint, v.url, '') AS endpoint
```

### 5. Score
```bash
python benchmark/score.py --findings findings.json
python benchmark/score.py --findings findings.json --target dvws-node
python benchmark/score.py --findings findings.json --min-p3-recall 60   # CI gate
```

## Findings JSON contract

A JSON array of objects. Recognized fields (first present wins):

| Concept  | Accepted keys |
|----------|---------------|
| target   | `target`, `targetName`, `project` |
| category | `category`, `type`, `vulnClass` |
| title    | `title`, `name`, `rule`, `ruleId` |
| severity | `severity` |
| endpoint | `endpoint`, `url`, `path`, `affectedUrl` |

A finding matches a ground-truth item when its **category equals** the item's
category **or** any of the item's **keywords appears** in the finding title/
category, **and** — when both carry an endpoint — the item's endpoint substring
appears in the finding's endpoint. Findings matching no catalog item are
reported separately as "additional" (extra true positives or false positives —
review by hand), never silently counted against recall.

## Interpreting the scorecard

- **P3+ recall** is the headline number for "medium-and-up" bug-bounty relevance.
- The **misses** list is the most useful output: it names exactly which planted
  vulns went undetected, so you can tell whether the gap is a module that wasn't
  enabled, a real detection weakness, or a business-logic class no scanner covers.
- Business-logic bugs (IDOR, mass assignment, broken access control) are where
  automated tooling is weakest — expect those to dominate the misses, and treat
  them as the manual-testing surface the tool's workflow is meant to *assist*,
  not replace.
