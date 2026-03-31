# Cadmux Security

Cadmux Security is a Python-based, Dockerized Linux security application with an initial **Nmap scanning** module and an extensible plugin architecture for adding future cybersecurity tooling.

## Why this architecture?

- **Scalable:** Plugins are registered through a tool manager (`PluginManager`) so adding tools like `nikto`, `gobuster`, or `trivy` is straightforward.
- **Reliable:** Input validation, subprocess timeout protection, structured error messages, bounded in-memory history, and app-level logging are included.
- **Container-first:** Runs in Docker and can be orchestrated with Docker Compose.
- **Themed UI:** Light-mode matrix-like aesthetic (green accents, monospace console design, subtle scanline background).

## Project structure

```text
.
├── app/
│   ├── core/
│   │   ├── models.py
│   │   └── plugin_manager.py
│   ├── plugins/
│   │   └── nmap_tool.py
│   ├── static/
│   │   └── styles.css
│   ├── templates/
│   │   └── index.html
│   └── main.py
├── tests/
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
└── .github/workflows/ci.yml
```

## Core features

1. **Nmap integration**
   - Uses subprocess execution (`nmap ... -oX -`) and parses XML output.
   - Supports predefined scan profiles:
     - `quick`: `-T4 -F`
     - `intense`: `-T4 -A -v`
     - `ports`: `-sV`
     - `ping`: `-sn`

2. **Input parameters**
   - Target: IP, CIDR, or hostname.
   - Scan profile: quick/intense/ports/ping.
   - Extra args: optional additional Nmap flags.

3. **Scalability model**
   - Implement new plugin classes with `scan(request)` and register with `PluginManager`.

4. **Reliability controls**
   - Target validation blocks unsafe shell characters.
   - Subprocess timeout is enforced (600s).
   - Errors surface in UI and are logged.

## Build & run

### Option 1: Docker Compose (recommended)

```bash
docker compose up --build
```

Open `http://localhost:5050`.

### Option 2: Docker CLI

```bash
docker build -t cadmux-security .
docker run --rm -p 5050:5050 cadmux-security
```

Open `http://localhost:5050`.

## Local development (without Docker)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
python -m app.main
```

Run tests:

```bash
pytest -q
```

## Theme implementation guidance

The matrix-like light theme is implemented in `app/static/styles.css` by combining:
- A pale background and white panels for accessibility.
- Green accent palette (`--accent`, `--accent-soft`) for matrix identity.
- Monospace typography.
- Repeating subtle horizontal scanline effect.

You can extend this with:
- CSS keyframe animation for low-opacity gradient drift.
- Dark/light toggle using CSS variables and a small JS controller.

## Extending with new cybersecurity tools

1. Add a new file in `app/plugins/`.
2. Implement a class exposing `name` and `scan(request)`.
3. Register it in `app/main.py` via `plugins.register(MyTool())`.
4. Add tool-specific form fields if needed.

## GitHub + ChatGPT Codex workflow

1. Create repo and push:

```bash
git init
git add .
git commit -m "Initial Cadmux Security platform"
git branch -M main
git remote add origin <YOUR_GITHUB_REPO_URL>
git push -u origin main
```

2. CI pipeline (`.github/workflows/ci.yml`) runs tests and verifies Docker build.
3. Use ChatGPT Codex to iterate on plugins, tests, and UI by opening issues/PRs and generating code suggestions.

## Security note

Run scans only on systems/networks you own or are explicitly authorized to test.

## One-command Linux auto-update deploy

Use the included script to pull the latest GitHub changes and redeploy the Docker service with a fresh build:

```bash
./deploy_update.sh
```

What it does:
- Verifies `git` and `docker` are installed.
- Ensures your working tree is clean.
- Pulls latest commits from `origin/<current-branch>`.
- Rebuilds and restarts containers using Docker Compose (`docker compose` or `docker-compose`).

Tip: run it manually after new commits are pushed, or schedule it with cron/systemd timer.
