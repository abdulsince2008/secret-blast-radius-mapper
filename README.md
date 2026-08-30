# Secret Blast-Radius Mapper

> **Problem:** Secret scanners (gitleaks, TruffleHog) tell you *what* leaked and *where*. They don't tell you **what breaks** when that secret is compromised — which services, deployments, CI pipelines, and infrastructure depend on it.

---

## Why This Is Different

| Tool | What It Does | Gap |
|------|-------------|-----|
| **gitleaks / TruffleHog** | Detect secrets in code/git history | No blast radius — you get a list of leaks, not an impact map |
| **GitGuardian / GitLeaks SaaS** | Cloud secret detection + alerting | Same: detection only, no dependency graph |
| **Secret Blast-Radius Mapper** | **Detects + traces git origin + maps config references → service dependency graph** | **Shows: "This AWS key leaks → backend, frontend, k8s, CI/CD all affected"** |

**The genuinely new piece:** After detection, we trace each secret to its **origin commit** (who introduced it, when), then parse **all config files** (.env, docker-compose, k8s, GitHub Actions, Helm) to build a **service dependency graph** — showing exactly which services, deployments, and pipelines would be compromised if that secret were exposed.

---

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐     ┌────────────────────┐
│  gitleaks   │────▶│  Git blame   │────▶│  Config parser   │────▶│  Dependency graph  │
│  (subproc)  │     │  (origin)    │     │  (.env, k8s,     │     │  (networkx)        │
└─────────────┘     └──────────────┘     │   docker-compose,│     └────────────────────┘
                                          │   GH Actions)    │
                                          └──────────────────┘
                                                    │
                                                    ▼
                                           ┌────────────────────┐
                                           │  Blast radius      │
                                           │  score + risk lvl  │
                                           └────────────────────┘
```

1. **Detect** — Runs `gitleaks detect` as a subprocess (uses your installed gitleaks binary)
2. **Trace origin** — Uses `git blame` + `git log -S` to find the commit that introduced each secret
3. **Parse configs** — Recursively scans for `.env*`, `docker-compose*.yml`, `k8s/**/*.yaml`, `.github/workflows/*.yml`, `helm/**/*.yaml`, `values*.yaml`
4. **Build graph** — Maps secret → config references → services → dependencies (shared secrets = implicit dependency)
5. **Score** — Computes blast radius score (0-100) based on secret type, hardcoded refs count, affected services, entropy

---

## How to Run It

### Prerequisites
- Python 3.10+
- `gitleaks` binary in PATH ([install](https://github.com/gitleaks/gitleaks#installation))
- A git repository to scan

### Install
```bash
git clone <this-repo>
cd secret-blast-radius-mapper
pip install -r requirements.txt
```

### Run
```bash
# Scan current directory (must be a git repo)
python -m src.cli .

# Scan a specific repo
python -m src.cli /path/to/repo

# Output JSON for CI/CD integration
python -m src.cli . --format json -o results.json

# Filter by minimum risk score
python -m src.cli . --min-score 50

# Tree view for exploration
python -m src.cli . --format tree
```

### Try the included sample repo
```bash
# First, initialize the sample repo as a git repository (one-time setup)
./setup_sample_repo.sh

# Then scan it
python -m src.cli sample_repo
```

---

## Example Output

```
$ python -m src.cli sample_repo
                          Secret Blast-Radius Analysis                          
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━┳━━━━┳━━━━┳━━━━┓
┃ Secret       ┃ File                   ┃ Origin            ┃ CR ┃ Sv ┃ Sc ┃ RI ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━╇━━━━╇━━╇━━━━┩
│ generic-api… │ backend/.env           ┃ 80d11e62 (Test    ┃ 21 ┃  7 ┃ 95 │ CR │
│              │                        ┃ User)             ┃    ┃    ┃    ┃    ┃
│ github-pat   │ backend/.env           ┃ 80d11e62 (Test    ┃  4 ┃  2 ┃ 75 │ CR │
│              │                        ┃ User)             ┃    ┃    ┃    ┃    ┃
│ slack-legac… │ backend/.env           ┃ 80d11e62 (Test    ┃  4 ┃  2 ┃ 65 │ HI │
│              │                        ┃ User)             ┃    ┃    ┃    ┃    ┃
│ stripe-acce… │ backend/.env           ┃ 80d11e62 (Test    ┃ 24 ┃  7 ┃ 85 │ CR │
│              │                        ┃ User)             ┃    ┃    ┃    ┃    ┃
│ aws-access-… │ backend/.env           ┃ 80d11e62 (Test    ┃ 24 ┃  7 ┃ 80 │ CR │
│              │                        ┃ User)             ┃    ┃    ┃    ┃    ┃
│ aws-access-… │ backend/config.py      ┃ 57f51c51 (Test    ┃ 24 ┃  7 ┃ 80 │ CR │
│              │                        ┃ User)             ┃    ┃    ┃    ┃    ┃
│ generic-api… │ infra/k8s/backend.yaml ┃ 80d11e62 (Test    ┃ 21 ┃  7 ┃ 95 │ CR │
│              │                        ┃ User)             ┃    ┃    ┃    ┃    ┃
└──────────────┴────────────────────────┴───────────────────┴────┴────┴────┴────┘

╭─────────────────────────── Finding Details ───────────────────────────╮
│ generic-api-key in backend/.env:6                                     │
│ Type: api_key | Preview: ghp_************************************abcd │
│ Origin: 80d11e62 by Test User on 2026-08-29T23:40:19+05:00            │
│ Blast Radius Score: 95 (CRITICAL)                                     │
╰───────────────────────────────────────────────────────────────────────╯
                               Config References                                
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━┓
┃ File         ┃ Type         ┃ Service      ┃ Variable     ┃ Line ┃ Hardcoded ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━┩
│ .../backend/ │ env          │ -            │ API_KEY      ┃    8 │     ✓     │
│ .../docker-c │ docker-comp  │ backend      │ AWS_ACCESS_… ┃    2 │     ✓     │
│ .../docker-c │ docker-comp  │ backend      │ AWS_SECRET_… ┃    3 │     ✓     │
│ .../infra/k8 │ kubernetes   │ production/… │ aws-access-… ┃    - │     ✓     │
│ .../.github/ │ github-acti  │ test         │ AWS_ACCESS_… ┃    - │     ✗     │
│ .../.github/ │ github-acti  │ test         │ AWS_SECRET_… ┃    - │     ✗     │
│ .../.github/ │ github-acti  │ build        │ AWS_ACCESS_… ┃    - │     ✗     │
│ .../.github/ │ github-acti  │ deploy       │ AWS_ACCESS_… ┃    - │     ✗     │
└──────────────┴──────────────┴──────────────┴──────────────┴──────┴───────────┘
                               Affected Services                                
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Service          ┃ Type         ┃ Config Files ┃ Env Vars ┃ Depends On       ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ production/bac…  │ k8s-workload │ 1            ┃ 5        ┃ -                │
│ test             │ ci-cd        │ 1            ┃ 5        ┃ backend, prod/…  │
│ build            │ ci-cd        │ 1            ┃ 3        ┃ prod/back, deploy│
│ deploy           │ ci-cd        │ 1            ┃ 2        ┃ prod/back, build │
│ backend          │ container    │ 1            ┃ 5        ┃ prod/back, test  │
│ frontend         │ container    │ 1            ┃ 2        ┃ unknown          │
└──────────────────┴──────────────┴──────────────┴──────────┴──────────────────┘
```

**Legend:** CR = Config Refs, Sv = Services, Sc = Blast Radius Score (0-100), RI = Risk Level (CRITICAL/HIGH/MEDIUM/LOW)

---

## Tech Stack + Libraries Reused

| Library | Purpose | Why Not Reinvent |
|---------|---------|------------------|
| **gitleaks** (subprocess) | Secret detection | Industry-standard, 100+ rules, actively maintained |
| **GitPython** | Git history / blame | Robust git operations, no shell parsing |
| **networkx** | Dependency graph | Battle-tested graph algorithms |
| **PyYAML** | Config parsing | Standard YAML library |
| **rich** | CLI output | Beautiful tables, trees, progress bars |

**Only ~600 lines of custom code** — the unique layer (origin tracing + config parsing + blast radius scoring).

---

## Known Limitations / What's Next

- [ ] **Deduplication**: Same secret in multiple files shows as separate findings (could group by fingerprint)
- [ ] **False positive filtering**: No baseline/.gitleaksignore support yet
- [ ] **More config types**: Terraform, Ansible, Helm values, ArgoCD, Flux
- [ ] **Secret validation**: Optionally verify secrets are still valid (AWS STS, GitHub API)
- [ ] **Remediation guidance**: Auto-generate rotation steps per service type
- [ ] **SBOM integration**: Cross-reference with CycloneDX/SPDX for supply chain view
- [ ] **Performance**: Large repos (>10k commits) can be slow on git log -S; add caching

---

## License

MIT — see [LICENSE](LICENSE)