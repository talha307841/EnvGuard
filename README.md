# EnvGuard

EnvGuard is a local background service that watches .env files and creates masked copies when access events occur.

It is designed to reduce accidental leakage of secrets during local development workflows.

## Features

- Watches configured directories for .env file events
- Masks secrets while preserving keys and structure
- Keeps original .env files unchanged
- Logs access activity with timestamp, process context, and file path
- Runs as a background daemon
- Supports startup registration on Linux, macOS, and Windows
- Provides a CLI for start, stop, status, logs, and directory management

## Masking Rules

- KEY=value becomes KEY=val*** by default
- Values shorter than 6 characters become KEY=***
- Safe keys are never masked by default:
	- NODE_ENV
	- PORT
	- HOST
	- APP_ENV
	- DEBUG
	- LOG_LEVEL
- Comments and blank lines are preserved as-is

## Ubuntu Setup

### 1. Install prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
```

### 2. Install EnvGuard (editable)

From the project root:

```bash
python3 -m pip install -e .
```

### 3. Verify CLI is available

```bash
envguard --version
```

## First-Time Configuration

Add one or more directories to watch:

```bash
envguard add ~/projects
envguard add ~/code
```

Inspect status:

```bash
envguard status
```

Default config location:

- ~/.envguard/config.json

Default log location:

- ~/.envguard/access.log

## Run on Ubuntu

### Start daemon manually

```bash
envguard start
```

### Stop daemon

```bash
envguard stop
```

### Check status + recent activity

```bash
envguard status
```

### Show full access log

```bash
envguard log
```

### Show last N log lines

```bash
envguard log --tail 50
```

## Enable Auto-Start on Ubuntu (systemd user service)

Register startup entry:

```bash
envguard install
```

This creates a user service file at:

- ~/.config/systemd/user/envguard.service

Useful systemd user commands:

```bash
systemctl --user status envguard
systemctl --user restart envguard
journalctl --user -u envguard -n 100 --no-pager
```

Remove startup entry:

```bash
envguard uninstall
```

## Test on Ubuntu End-to-End

### 1. Start service and add a watch directory

```bash
envguard add ~/projects
envguard start
```

### 2. Create a sample .env in watched path

```bash
mkdir -p ~/projects/envguard-demo
cat > ~/projects/envguard-demo/.env << 'EOF'
# demo file
NODE_ENV=production
PORT=3000
API_KEY=myverylongsecretkey
DB_PASSWORD=supersecretpassword
EOF
```

### 3. Trigger file open/read event

```bash
cat ~/projects/envguard-demo/.env > /dev/null
```

### 4. Check status and logs

```bash
envguard status
envguard log --tail 20
```

Expected behavior:

- Access attempts are logged in ~/.envguard/access.log
- A masked temp copy is created near the source file
- Original .env file remains unchanged

## Manual Masking Command

Mask a single file into a temp output:

```bash
envguard mask ~/projects/envguard-demo/.env
```

Preview changes without writing a file:

```bash
envguard mask ~/projects/envguard-demo/.env --dry-run
```

## CLI Commands

```bash
envguard start
envguard stop
envguard status
envguard add <path>
envguard log
envguard install
envguard uninstall
envguard mask <file> [--dry-run]
```

## Run Tests

```bash
python -m pytest -q
```

## Troubleshooting (Ubuntu)

- Command not found after install:
	- Re-open your shell, or run:
		- python3 -m pip install -e .

- Service not running:
	- Check status:
		- envguard status
	- Check user service:
		- systemctl --user status envguard

- No log entries:
	- Ensure watched directories are configured:
		- envguard status
	- Ensure .env files are inside watched directories

## Notes

- EnvGuard masks file content into temp files; it does not modify originals.
- Detection depends on filesystem event visibility and platform backend behavior.