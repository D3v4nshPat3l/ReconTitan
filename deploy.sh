#!/usr/bin/env bash
# ReconTitan production deployment for Ubuntu 22.04/24.04.
set -Eeuo pipefail
umask 077

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }
trap 'fail "Deployment stopped near line $LINENO"' ERR

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "Run as root: sudo ./deploy.sh"

read -r -p "Enter your public domain (example: scanner.example.com): " DOMAIN
DOMAIN=${DOMAIN,,}
[[ "$DOMAIN" =~ ^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || fail "Enter a valid public domain"
read -r -p "Enter your email for Let's Encrypt: " SSL_EMAIL
[[ "$SSL_EMAIL" == *@*.* ]] || fail "Enter a valid email address"

log "Installing required packages"
apt-get update -qq
apt-get install -y -qq ca-certificates curl certbot openssl ufw gnupg

if ! command -v docker >/dev/null 2>&1; then
    log "Configuring Docker's signed apt repository"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    . /etc/os-release
    DOCKER_SUITE=${UBUNTU_CODENAME:-$VERSION_CODENAME}
    cat > /etc/apt/sources.list.d/docker.sources <<DOCKEREOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $DOCKER_SUITE
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
DOCKEREOF
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is not installed"

log "Configuring firewall"
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment SSH
ufw allow 80/tcp comment HTTP
ufw allow 443/tcp comment HTTPS
ufw --force enable

if [[ -f .env ]]; then
    warn "An existing .env was found; keeping it as .env.bak before regenerating"
    cp -a .env ".env.bak.$(date +%Y%m%d%H%M%S)"
fi

log "Generating production secrets"
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
API_ACCESS_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
REDIS_PASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(40))')
MONGO_ROOT_PASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(40))')
MONGO_PASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(40))')
ADMIN_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
cat > .env <<ENVEOF
RECONTITAN_DEBUG=false
DOMAIN=$DOMAIN
SECRET_KEY=$SECRET_KEY
API_ACCESS_KEY=$API_ACCESS_KEY
TRUSTED_HOSTS=$DOMAIN,www.$DOMAIN
CORS_ORIGINS=https://$DOMAIN
CORS_ALLOW_CREDENTIALS=false
ALLOW_PRIVATE_TARGETS=false
ENABLE_ACTIVE_VULN_TOOLS=false
MAX_REQUEST_BODY_BYTES=2097152

REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=$REDIS_PASS
MONGO_ROOT_USER=recontitan_root
MONGO_ROOT_PASS=$MONGO_ROOT_PASS
MONGO_HOST=mongo
MONGO_PORT=27017
MONGO_DB=recontitan
MONGO_USER=recontitan_app
MONGO_PASS=$MONGO_PASS
MONGO_AUTH_SOURCE=recontitan

# Admin surface. Published to host loopback only and never proxied by nginx,
# so it has no public route. Reach it with an SSH tunnel:
#   ssh -N -L 9000:127.0.0.1:9000 root@$DOMAIN
# then open http://127.0.0.1:9000/admin/ on your own machine.
ADMIN_ENABLED=true
ADMIN_TOKEN=$ADMIN_TOKEN
ADMIN_PORT=9000
ADMIN_MAX_FAILURES=5
ADMIN_LOCKOUT_SECONDS=900

# Audit trail
AUDIT_ENABLED=true
AUDIT_RETENTION_DAYS=90

# Danger Mode. Left disabled deliberately: it sends bounded penetration-test
# simulation traffic and must be a conscious decision per deployment. Set to
# true ONLY for targets you own or hold written authorization to assess, then
# run: docker compose up -d --force-recreate api worker
ALLOW_DANGER_MODE=true
DANGER_MAX_SCAN_SECONDS=240
DANGER_MAX_REQUESTS_TOTAL=500
DANGER_REQUEST_DELAY_MS=150

# Scan performance
SCAN_TOOL_CONCURRENCY=8
HTTP_POOL_MAX_IDLE=16
DNS_CACHE_TTL_SECONDS=30

API_HOST=0.0.0.0
API_PORT=8000
SCAN_TIMEOUT_NMAP=300
SCAN_TIMEOUT_NUCLEI=600
SCAN_TIMEOUT_DEFAULT=120
JS_ANALYSIS_MAX_FILES=20
JS_ANALYSIS_MAX_BYTES=1048576
TAKEOVER_MAX_SUBDOMAINS=150

OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
GREYNOISE_API_KEY=
SECURITYTRAILS_API_KEY=
URLSCAN_API_KEY=
INTELX_API_KEY=
ENVEOF
chmod 600 .env

mkdir -p nginx/certs
log "Obtaining a Let's Encrypt certificate"
docker compose down --remove-orphans >/dev/null 2>&1 || true
fuser -k 80/tcp >/dev/null 2>&1 || true
if certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --email "$SSL_EMAIL" --preferred-challenges http; then
    ln -sfn "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" nginx/certs/fullchain.pem
    ln -sfn "/etc/letsencrypt/live/$DOMAIN/privkey.pem" nginx/certs/privkey.pem
else
    warn "Let's Encrypt failed; generating a temporary self-signed certificate"
    rm -f nginx/certs/fullchain.pem nginx/certs/privkey.pem
    openssl req -x509 -nodes -days 30 -newkey rsa:3072 \
        -keyout nginx/certs/privkey.pem -out nginx/certs/fullchain.pem \
        -subj "/CN=$DOMAIN" >/dev/null 2>&1
fi

log "Validating configuration"
docker compose config --quiet
bash -n deploy.sh

log "Building and starting services"
docker compose build --pull
docker compose up -d

for _ in $(seq 1 40); do
    if docker compose exec -T api curl -fsS http://localhost:8000/api/health >/dev/null 2>&1; then
        ok "API health check passed"
        break
    fi
    sleep 3
done
docker compose exec -T api curl -fsS http://localhost:8000/api/health >/dev/null || fail "API failed health check; run docker compose logs api"

WORKDIR=$(pwd)
cat > /etc/systemd/system/recontitan.service <<UNIT
[Unit]
Description=ReconTitan
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$WORKDIR
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable recontitan >/dev/null

cat > /etc/cron.d/recontitan-ssl-renew <<CRON
17 3 * * * root certbot renew --quiet --deploy-hook 'cd $WORKDIR && docker compose exec -T nginx nginx -s reload'
CRON
chmod 644 /etc/cron.d/recontitan-ssl-renew

ok "ReconTitan is available at https://$DOMAIN"
warn "Browser API access key (store securely): $API_ACCESS_KEY"
warn "Admin token (store securely, shown once): $ADMIN_TOKEN"
echo
log "The admin surface has no public route. To reach it:"
echo "    ssh -N -L 9000:127.0.0.1:9000 root@$DOMAIN"
echo "    then open http://127.0.0.1:9000/admin/ locally"
