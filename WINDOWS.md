# Running on Windows

**Short version: yes, it runs on Windows — the easy way is Docker Desktop.**
Every service (API, workers, database, cache, and *all* the security scan
tools) runs inside Linux containers, so you install **nothing** on Windows
except Docker Desktop. The scan tools are baked into the container image — you
never touch them on your host.

---

## 1. Install the one prerequisite

| Tool | Why | Where |
|---|---|---|
| **Docker Desktop** (includes Docker Engine + Compose + the WSL 2 backend) | Runs the whole stack | https://www.docker.com/products/docker-desktop/ |

Docker Desktop's installer enables **WSL 2** for you. If it prompts you to
install the WSL 2 kernel update, accept it (or run `wsl --install` in an
admin PowerShell once). That's the only setup — you do **not** install Go,
Python, PostgreSQL, Redis, nmap, subfinder, or any scanner on Windows.

## 2. Set it up (PowerShell, in the repo folder)

```powershell
git clone <this-repo-url>
cd DNM-DEFENCE

.\scripts\dnm.ps1 setup          # writes backend\.env with secure random secrets
.\scripts\dnm.ps1 up             # builds and starts the whole stack
.\scripts\dnm.ps1 create-admin   # prompts for your first admin email + password
.\scripts\dnm.ps1 health         # confirms everything is running
```

Then open **http://localhost** and log in.

> If PowerShell says *"running scripts is disabled on this system"*, run this
> once and retry:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```
> Prefer `cmd.exe`? Use the wrapper instead: `scripts\dnm.bat up`

`.\scripts\dnm.ps1 help` lists every command (`up`, `down`, `logs`, `health`,
`create-admin`, `backup`, `restore`, `rebuild`, …) — it's the Windows
equivalent of the `make` targets used on Linux/macOS.

## 3. Two things to set for real use (in `backend\.env`)

1. **`ANTHROPIC_API_KEY`** — required for AI reports, executive summaries, and
   narratives. Everything else works without it. Run `.\scripts\dnm.ps1 restart`
   after editing.
2. **`ALLOWED_ORIGINS`** — to serve the portal to remote users (not just this
   PC), set it to your domain/IP, e.g. `ALLOWED_ORIGINS=https://portal.youragency.com`.

---

## What gets installed *inside* the container (you don't install these)

These are pulled in automatically by `backend/Dockerfile` when you run
`dnm.ps1 up` — listed so you know what's running:

**Core recon (Module 1) — always installed**
- `subfinder`, `httpx`, `naabu`, `nuclei`, `amass` (Go recon tools)
- `nmap`, `dnsutils` (`dig`)

**Analyzers (Expanded/Advanced services) — installed via `requirements.txt`**
- `androguard` (mobile APK/DEX), `slither-analyzer` + `semgrep` (Solidity /
  patterns), `checkov` (IaC), `python-evtx` (Windows event logs), `binwalk`
  (firmware)

**Optional deeper-enrichment tools** *(installed by default; skip with
`--build-arg INSTALL_OPTIONAL_TOOLS=false` for a smaller image)*
- `trufflehog`, `kube-score`, `kubesec`, `hadolint`, `apktool`, `jadx`,
  `mythril`, `checksec`

**Optional API keys** (each integration degrades gracefully if its key is
empty — set only what you need in `backend\.env`): `SHODAN_API_KEY`,
`HIBP_API_KEY`, `CENSYS_API_ID`/`CENSYS_API_SECRET`, `GITHUB_TOKEN`,
`VIRUSTOTAL_API_KEY`, `SENDGRID_API_KEY` (email alerts), `SLACK_BOT_TOKEN`.

---

## Notes & troubleshooting

- **Port 80 in use?** If something else on Windows uses port 80 (IIS, Skype),
  edit `docker-compose.yml` → the `frontend` service `ports:` to e.g.
  `"8080:80"`, then browse to `http://localhost:8080`.
- **First `up` is slow** — it builds the image and installs every tool. Later
  starts are fast.
- **Keep Docker Desktop running** while you use the platform.
- **Backups** land in `.\backups\` as `.sql` files (`dnm.ps1 backup` /
  `restore -Backup <file>`).

## The "manual" path (NOT recommended on Windows)

Running the services directly on Windows (without Docker) is painful and
unsupported: **Celery** dropped official Windows support (needs
`--pool=solo`), **Redis** has no official Windows build, and several scan
tools (`checksec`, `binwalk`) are Linux-only. If you must avoid Docker
Desktop, run everything inside **WSL 2 (Ubuntu)** and follow the Linux
"Option B" steps in `README.md` there — but Docker Desktop is the intended,
tested-shape Windows path.
