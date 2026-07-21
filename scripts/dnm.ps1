<#
  dnm.ps1 — Windows operator commands for the Track 1 Security Platform.

  The Windows equivalent of the Makefile: same workflow, no `make` required.
  Everything runs in Docker Desktop's Linux containers, so you install NOTHING
  on Windows except Docker Desktop — all the scan tools live inside the image.

  Usage (from a PowerShell window, in the repo root):
      .\scripts\dnm.ps1 setup          # once: writes backend\.env with secure secrets
      .\scripts\dnm.ps1 up             # build + start the whole stack
      .\scripts\dnm.ps1 create-admin   # your first login
      .\scripts\dnm.ps1 health         # confirm everything is running
      .\scripts\dnm.ps1 help           # list all commands

  If PowerShell blocks the script ("running scripts is disabled"), run once:
      Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#>

param(
  [Parameter(Position = 0)]
  [string]$Command = "help",
  [string]$Backup
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent
$EnvPath = Join-Path $RepoRoot "backend\.env"
$ExamplePath = Join-Path $RepoRoot "backend\.env.example"

function Write-Info($m) { Write-Host $m -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host $m -ForegroundColor Green }
function Write-Warn($m) { Write-Host $m -ForegroundColor Yellow }

function Assert-Docker {
  try { docker version *> $null } catch {
    throw "Docker isn't running. Install Docker Desktop and start it first: https://www.docker.com/products/docker-desktop/"
  }
  try { docker compose version *> $null } catch {
    throw "Docker Compose v2 not found. Update Docker Desktop to a recent version."
  }
}

# --- secure secret generation (no Python needed on the host) ---
function New-RandomBytes([int]$n) {
  $bytes = New-Object 'System.Byte[]' $n
  $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return $bytes
}
function New-SecretKey {
  # 48 random bytes, url-safe base64, no padding — signs auth tokens.
  ([Convert]::ToBase64String((New-RandomBytes 48))).Replace('+','-').Replace('/','_').TrimEnd('=')
}
function New-FernetKey {
  # 32 random bytes, url-safe base64 WITH padding — exactly what Fernet expects.
  ([Convert]::ToBase64String((New-RandomBytes 32))).Replace('+','-').Replace('/','_')
}

function Read-EnvValues([string]$path) {
  $h = @{}
  if (Test-Path $path) {
    foreach ($line in Get-Content $path) {
      $t = $line.Trim()
      if ($t -and -not $t.StartsWith('#') -and $t.Contains('=')) {
        $k, $v = $t.Split('=', 2)
        $h[$k.Trim()] = $v.Trim()
      }
    }
  }
  return $h
}

function Invoke-Setup {
  if (-not (Test-Path $ExamplePath)) { throw "Missing backend\.env.example — run this from the repo root." }

  $existing = Read-EnvValues $EnvPath
  if ($existing.Count -gt 0) { Write-Info "Found existing backend\.env — preserving $($existing.Count) already-set value(s)." }

  # In the Docker network services reach each other by service name, not localhost.
  $dockerDefaults = @{
    'DATABASE_URL'          = 'postgresql://track1:track1@db:5432/track1'
    'REDIS_URL'             = 'redis://redis:6379/0'
    'CELERY_BROKER_URL'     = 'redis://redis:6379/0'
    'CELERY_RESULT_BACKEND' = 'redis://redis:6379/1'
    'ENV'                   = 'production'
    'DEBUG'                 = 'false'
    'ALLOWED_ORIGINS'       = 'http://localhost'
  }

  $genCount = 0; $dockCount = 0
  $out = New-Object System.Collections.Generic.List[string]
  foreach ($line in Get-Content $ExamplePath) {
    $m = [regex]::Match($line, '^([A-Z0-9_]+)=(.*)$')
    if (-not $m.Success) { $out.Add($line); continue }
    $key = $m.Groups[1].Value

    if ($existing.ContainsKey($key) -and $existing[$key] -ne '') {
      $out.Add("$key=$($existing[$key])")
    } elseif ($key -eq 'SECRET_KEY') {
      $out.Add("SECRET_KEY=$(New-SecretKey)"); $genCount++
    } elseif ($key -eq 'ENCRYPTION_KEY') {
      $out.Add("ENCRYPTION_KEY=$(New-FernetKey)"); $genCount++
    } elseif ($dockerDefaults.ContainsKey($key)) {
      $out.Add("$key=$($dockerDefaults[$key])"); $dockCount++
    } else {
      $out.Add($line)
    }
  }

  # Write UTF-8 without BOM so the container parses it cleanly.
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($EnvPath, ($out -join "`n") + "`n", $enc)

  Write-Ok "Wrote backend\.env"
  Write-Host "  - generated $genCount secure secret(s) (SECRET_KEY, ENCRYPTION_KEY)"
  Write-Host "  - set $dockCount Docker-network default(s)"
  $final = Read-EnvValues $EnvPath
  $ai = $final['ANTHROPIC_API_KEY']
  if (-not $ai -or $ai -in @('your-api-key-here','test-key-for-local-verification')) {
    Write-Warn "`n  NOTE: ANTHROPIC_API_KEY is not set to a real key yet. Everything except"
    Write-Warn "        AI reports/summaries works without it — set it in backend\.env to enable them."
  }
  Write-Host "`nNext:  .\scripts\dnm.ps1 up   then   .\scripts\dnm.ps1 create-admin   then open http://localhost"
}

# --- run everything from the repo root so compose finds its file ---
Push-Location $RepoRoot
try {
  switch ($Command.ToLower()) {
    "setup" { Invoke-Setup }

    "up" {
      Assert-Docker
      docker compose up -d --build
      Write-Ok "`nStack starting. Run '.\scripts\dnm.ps1 health' in ~30s, then open http://localhost"
    }
    "down"    { Assert-Docker; docker compose down }
    "restart" { Assert-Docker; docker compose restart }
    "rebuild" { Assert-Docker; docker compose up -d --build }
    "logs"    { Assert-Docker; docker compose logs -f --tail=100 }
    "ps"      { Assert-Docker; docker compose ps }

    "health" {
      Assert-Docker
      Write-Info "--- API liveness ---"
      try {
        $r = Invoke-WebRequest -UseBasicParsing -Uri "http://localhost/health" -TimeoutSec 5
        Write-Ok $r.Content
      } catch { Write-Warn "API not reachable yet (give it ~30s after 'up')." }
      Write-Info "--- container status ---"
      docker compose ps
    }

    "create-admin" {
      Assert-Docker
      $email = Read-Host "Admin email"
      docker compose run --rm api python -m app.scripts.create_admin $email
    }

    "migrate"   { Assert-Docker; docker compose run --rm api alembic upgrade head }
    "shell-api" { Assert-Docker; docker compose exec api sh }
    "test"      { Assert-Docker; docker compose run --rm api pytest -q }

    "backup" {
      Assert-Docker
      $dir = Join-Path $RepoRoot "backups"
      if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
      $ts = Get-Date -Format "yyyyMMdd_HHmmss"
      $file = Join-Path $dir "track1_$ts.sql"
      # cmd /c gives clean byte redirection (PowerShell '>' can mangle encoding on 5.1).
      cmd /c "docker compose exec -T db pg_dump -U track1 track1 > `"$file`""
      Write-Ok "Wrote $file"
    }
    "restore" {
      Assert-Docker
      if (-not $Backup) { throw "Usage: .\scripts\dnm.ps1 restore -Backup backups\track1_<ts>.sql" }
      if (-not (Test-Path $Backup)) { throw "File not found: $Backup" }
      cmd /c "docker compose exec -T db psql -U track1 track1 < `"$Backup`""
      Write-Ok "Restored from $Backup"
    }

    default {
      Write-Host "Track 1 Security Platform — Windows commands`n"
      Write-Host "  setup         First-run: generate backend\.env with secure random secrets"
      Write-Host "  up            Build and start the whole stack"
      Write-Host "  down          Stop and remove all containers (data kept)"
      Write-Host "  restart       Restart every service (picks up .env changes)"
      Write-Host "  rebuild       Rebuild images and restart"
      Write-Host "  logs          Tail logs from all services (Ctrl-C to stop)"
      Write-Host "  ps            Show the status of every service"
      Write-Host "  health        Check API health + container status"
      Write-Host "  create-admin  Create your first admin login"
      Write-Host "  migrate       Apply database migrations"
      Write-Host "  shell-api     Open a shell inside the API container"
      Write-Host "  backup        Dump the database to .\backups\"
      Write-Host "  restore       Restore from a dump (-Backup <path>)"
      Write-Host "  test          Run the backend test suite in the API image"
      Write-Host "`nExample:  .\scripts\dnm.ps1 setup"
    }
  }
}
finally { Pop-Location }
