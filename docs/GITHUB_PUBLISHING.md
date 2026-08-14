# Publish ReconTitan to GitHub with Git Bash

This guide assumes the project was extracted to:

```text
C:\Users\devan\Downloads\ReconTitan-Enhanced-v0.4.1
```

## Before you begin

Install:

1. Git for Windows
2. GitHub CLI (`gh`)
3. A browser for GitHub authentication

Open Git Bash and verify:

```bash
git --version
gh --version
```

## Configure your Git identity

Use the name and email associated with the GitHub account that will own the commits:

```bash
git config --global user.name "YOUR_GITHUB_USERNAME"
git config --global user.email "YOUR_GITHUB_EMAIL"
```

Confirm:

```bash
git config --global --list
```

## Open the extracted folder

```bash
cd /c/Users/devan/Downloads/ReconTitan-Enhanced-v0.4.1
pwd
ls
```

You should see `README.md`, `backend`, `frontend`, and `docker-compose.yml`.

## Initialize and commit the project

```bash
git init
git branch -M main
git status
git add .
git status
git commit -m "feat: release ReconTitan 0.4.1"
```

Before `git add .`, verify that `.env` is ignored and not listed. Never push real API keys, passwords, scan reports, or customer targets.

## Sign in to GitHub CLI

```bash
gh auth login
```

Choose:

1. `GitHub.com`
2. `HTTPS`
3. `Login with a web browser`
4. Copy the one-time code and complete the browser login

Then verify the correct account:

```bash
gh auth status
gh api user --jq .login
```

## Create a new public repository and push

Replace `YOUR_GITHUB_USERNAME` if necessary:

```bash
gh repo create YOUR_GITHUB_USERNAME/ReconTitan \
  --public \
  --source=. \
  --remote=origin \
  --description "Security-hardened external reconnaissance and web assessment platform" \
  --push
```

Open it:

```bash
gh repo view --web
```

## Push to a repository that already exists

Do not run `gh repo create`. Add or correct the remote:

```bash
git remote -v
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/ReconTitan.git
```

If `origin` already exists:

```bash
git remote set-url origin https://github.com/YOUR_GITHUB_USERNAME/ReconTitan.git
```

Then push:

```bash
git push -u origin main
```

## Publish later updates

```bash
cd /c/Users/devan/Downloads/ReconTitan-Enhanced-v0.4.1
git status
git add .
git commit -m "fix: describe the update"
git push
```

## Recommended feature-branch workflow

```bash
git switch -c feature/my-change
# edit files and run tests
git add .
git commit -m "feat: describe the change"
git push -u origin feature/my-change
gh pr create --fill --draft
```

## Common errors

### `remote origin already exists`

```bash
git remote set-url origin https://github.com/YOUR_GITHUB_USERNAME/ReconTitan.git
```

### `repository not found`

Check the repository spelling and verify the authenticated account:

```bash
gh auth status
gh api user --jq .login
git remote -v
```

### Wrong GitHub account is active

```bash
gh auth logout
gh auth login
gh api user --jq .login
```

### Accidentally staged `.env`

```bash
git restore --staged .env
```

If a secret was already pushed, remove it from the repository and rotate the secret immediately. Deleting only the visible file does not remove it from Git history.
