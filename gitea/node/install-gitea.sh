#!/bin/bash
# Установка Gitea в образ узла git (Debian 12) для лабы с git.
#
# Запускается один раз от root на шаблонной ВМ, затем ВМ выключают и образ
# сохраняют. В образе сразу всё готово, подготовка лабы на этом узле не нужна:
#   - Gitea на порту PORT (только HTTP, вход по паролю), сервис gitea;
#   - шаблон ORG/REPO — открыт всем на чтение, писать могут только админы;
#   - студент STUDENT_LOGIN / STUDENT_PASS (одинаковые во всех лабах) и его
#     пустой приватный репозиторий STUDENT_LOGIN/REPO; других репозиториев и
#     организаций он создавать не может;
#   - админ ADMIN со случайным паролем: /root/gitea-admin.txt.
# Адрес узла (DHCP на ens3) заранее не известен: ссылки Gitea строит по
# адресу из запроса (PUBLIC_URL_DETECTION = auto).
#
# Что положить на веб-сервер (BASE_URL):
#   gitea-1.24.6-linux-amd64  — https://dl.gitea.com/gitea/1.24.6/gitea-1.24.6-linux-amd64
#   portals.tar.gz            — tar czf portals.tar.gz -C gitea/setup portals
#
# Запуск: BASE_URL=http://10.19.36.2/gitea bash install-gitea.sh
# Повторный запуск безопасен: что уже создано, не пересоздаётся.
set -euo pipefail

# ------------------------------------------------------------------ параметры
BASE_URL=${BASE_URL:-http://10.19.36.2/gitea}
GITEA_VERSION=${GITEA_VERSION:-1.24.6}
GITEA_BIN_URL=${GITEA_BIN_URL:-$BASE_URL/gitea-$GITEA_VERSION-linux-amd64}
# sha256 бинарника 1.24.6; пусто — не проверять (для другой версии)
GITEA_SHA256=${GITEA_SHA256-bb09d565d7e22ed07a9525d22e6f7c468ec00b58484a9691d61ff70940452676}
TEMPLATE_URL=${TEMPLATE_URL:-$BASE_URL/portals.tar.gz}
PACKAGES=${PACKAGES:-git curl qemu-guest-agent}
PORT=${PORT:-3000}
ORG=${ORG:-course}
REPO=${REPO:-portals}
ADMIN=${ADMIN:-labadmin}
STUDENT_LOGIN=${STUDENT_LOGIN:-student}
STUDENT_PASS=${STUDENT_PASS:-student123}
EMAIL_DOMAIN=${EMAIL_DOMAIN:-lab.local}

BIN=/usr/local/bin/gitea
CONF=/etc/gitea/app.ini
WORK=/var/lib/gitea
HOME_GIT=/home/git
ADMIN_FILE=/root/gitea-admin.txt
API=http://localhost:$PORT/api/v1

die() { echo "ОШИБКА: $*" >&2; exit 1; }
log() { echo "== $*"; }
as_git() { runuser -u git -- env HOME=$HOME_GIT GITEA_WORK_DIR=$WORK "$@"; }
gen_pass() {
    head -c 512 /dev/urandom | LC_ALL=C tr -dc 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789' | cut -c 1-16
}

[ "$(id -u)" = 0 ] || die "запускайте от root"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ------------------------------------------------------------------ пакеты
missing=()
for p in $PACKAGES; do
    dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
done
if [ ${#missing[@]} -gt 0 ]; then
    log "Ставлю пакеты: ${missing[*]}"
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${missing[@]}"
fi
command -v qemu-ga >/dev/null && systemctl enable qemu-guest-agent >/dev/null 2>&1 || true

# ------------------------------------------------------------------ бинарник
if [ ! -x "$BIN" ] || ! "$BIN" --version 2>/dev/null | grep -q "version $GITEA_VERSION "; then
    log "Скачиваю $GITEA_BIN_URL"
    curl -fsSL -o "$TMP/gitea" "$GITEA_BIN_URL"
    if [ -n "$GITEA_SHA256" ]; then
        echo "$GITEA_SHA256  $TMP/gitea" | sha256sum -c --quiet - || die "sha256 бинарника не совпадает"
    fi
    install -m 755 "$TMP/gitea" "$BIN"
fi

# ------------------------------------------------------------------ пользователь и каталоги
if ! id git >/dev/null 2>&1; then
    log "Создаю пользователя git"
    adduser --system --shell /bin/bash --gecos 'Gitea' --group --disabled-password --home "$HOME_GIT" git >/dev/null
fi
install -d -o git -g git -m 750 "$WORK" "$WORK/custom" "$WORK/data" "$WORK/log"
install -d -o root -g git -m 750 /etc/gitea

# ------------------------------------------------------------------ app.ini
if [ ! -f "$CONF" ]; then
    log "Пишу $CONF"
    cat > "$CONF" <<EOF
APP_NAME = Git лабы
RUN_USER = git
RUN_MODE = prod
WORK_PATH = $WORK

[server]
PROTOCOL = http
HTTP_PORT = $PORT
ROOT_URL = http://localhost:$PORT/
PUBLIC_URL_DETECTION = auto
DISABLE_SSH = true
START_SSH_SERVER = false
OFFLINE_MODE = true
LFS_START_SERVER = false
APP_DATA_PATH = $WORK/data

[database]
DB_TYPE = sqlite3
PATH = $WORK/data/gitea.db

[repository]
ROOT = $WORK/data/gitea-repositories
DEFAULT_BRANCH = main
ENABLE_PUSH_CREATE_USER = false
ENABLE_PUSH_CREATE_ORG = false

[security]
INSTALL_LOCK = true
SECRET_KEY = $("$BIN" generate secret SECRET_KEY)
INTERNAL_TOKEN = $("$BIN" generate secret INTERNAL_TOKEN)
PASSWORD_COMPLEXITY = off
MIN_PASSWORD_LENGTH = 6
PASSWORD_CHECK_PWN = false

[service]
DISABLE_REGISTRATION = true
REQUIRE_SIGNIN_VIEW = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = false
DEFAULT_KEEP_EMAIL_PRIVATE = true
ENABLE_NOTIFY_MAIL = false

[mailer]
ENABLED = false

[oauth2]
ENABLED = false
JWT_SECRET = $("$BIN" generate secret JWT_SECRET)

[openid]
ENABLE_OPENID_SIGNIN = false
ENABLE_OPENID_SIGNUP = false

[api]
ENABLE_SWAGGER = false

[cron.update_checker]
ENABLED = false

[other]
SHOW_FOOTER_VERSION = false

[log]
MODE = console
LEVEL = warn
ROOT_PATH = $WORK/log
EOF
    chown root:git "$CONF"
    chmod 640 "$CONF"
fi

# ------------------------------------------------------------------ сервис
cat > /etc/systemd/system/gitea.service <<EOF
[Unit]
Description=Gitea
After=network.target

[Service]
Type=simple
User=git
Group=git
WorkingDirectory=$WORK
ExecStart=$BIN web --config $CONF
Restart=always
Environment=USER=git HOME=$HOME_GIT GITEA_WORK_DIR=$WORK

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable gitea >/dev/null 2>&1
systemctl restart gitea

log "Жду Gitea"
for _ in $(seq 60); do
    curl -sf "$API/version" >/dev/null && break
    sleep 1
done
curl -sf "$API/version" >/dev/null || die "Gitea не отвечает на $API (journalctl -u gitea)"

# ------------------------------------------------------------------ админ
if [ ! -f "$ADMIN_FILE" ]; then
    if as_git "$BIN" admin user list --config "$CONF" --admin | awk 'NR > 1 {print $2}' | grep -qx "$ADMIN"; then
        die "админ $ADMIN уже есть, но нет $ADMIN_FILE"
    fi
    log "Создаю админа $ADMIN"
    pass=$(gen_pass)
    as_git "$BIN" admin user create --config "$CONF" --admin --username "$ADMIN" --password "$pass" \
        --email "$ADMIN@$EMAIL_DOMAIN" --must-change-password=false >/dev/null
    (umask 077; printf '%s %s\n' "$ADMIN" "$pass" > "$ADMIN_FILE")
fi
read -r _ ADMIN_PASS < "$ADMIN_FILE"

# api МЕТОД ПУТЬ [JSON] -> код ответа; тело в $TMP/body
api() {
    curl -sS -o "$TMP/body" -w '%{http_code}' -X "$1" -u "$ADMIN:$ADMIN_PASS" \
        -H 'Content-Type: application/json' ${3:+--data "$3"} "$API$2"
}
# api_ok ОПИСАНИЕ КОД_ОТВЕТА ДОПУСТИМЫЕ_КОДЫ...
api_ok() {
    local what=$1 code=$2; shift 2
    for c in "$@"; do [ "$code" = "$c" ] && return 0; done
    die "$what: HTTP $code: $(cat "$TMP/body")"
}
# ensure ОПИСАНИЕ ПУТЬ_GET ПУТЬ_POST JSON: создать, если нет
ensure() {
    local code
    code=$(api GET "$2")
    if [ "$code" = 404 ]; then
        log "Создаю $1"
        code=$(api POST "$3" "$4")
        api_ok "$1" "$code" 201
    else
        api_ok "$1" "$code" 200
    fi
}

# ------------------------------------------------------------------ шаблон
ensure "организацию $ORG" "/orgs/$ORG" /orgs \
    "{\"username\":\"$ORG\",\"full_name\":\"Курс\",\"visibility\":\"public\"}"
ensure "шаблон $ORG/$REPO" "/repos/$ORG/$REPO" "/orgs/$ORG/repos" \
    "{\"name\":\"$REPO\",\"private\":false,\"default_branch\":\"main\",\"description\":\"Шаблон: четыре портала (только чтение)\"}"

# Флаг empty в API обновляется с задержкой, поэтому смотрим ветки напрямую
TPL_URL="http://$ADMIN:$ADMIN_PASS@localhost:$PORT/$ORG/$REPO.git"
if [ -z "$(git ls-remote --heads "$TPL_URL")" ]; then
    log "Заливаю шаблон из $TEMPLATE_URL"
    curl -fsSL -o "$TMP/portals.tar.gz" "$TEMPLATE_URL"
    tar xzf "$TMP/portals.tar.gz" -C "$TMP"
    src=$TMP/portals
    [ -f "$src/README.md" ] || die "в архиве нет portals/README.md"
    w=$TMP/tpl
    mkdir -p "$w"
    g() { git -C "$w" -c user.name="Курс" -c user.email="$ORG@$EMAIL_DOMAIN" "$@"; }
    g init -q -b main
    # История из нескольких коммитов: у студента она должна сохраниться
    cp -r "$src/README.md" "$src/shop" "$src/blog" "$w/"
    g add -A && g commit -qm "Порталы shop и blog"
    cp -r "$src/wiki" "$src/news" "$w/"
    g add -A && g commit -qm "Порталы wiki и news"
    cp -r "$src/nginx" "$w/"
    g add -A && g commit -qm "Конфиги nginx для порталов"
    g push -q "$TPL_URL" main 2>/dev/null
fi

# ------------------------------------------------------------------ студент
ensure "пользователя $STUDENT_LOGIN" "/users/$STUDENT_LOGIN" /admin/users \
    "{\"username\":\"$STUDENT_LOGIN\",\"email\":\"$STUDENT_LOGIN@$EMAIL_DOMAIN\",\"password\":\"$STUDENT_PASS\",\"must_change_password\":false}"
# Пароль и ограничения выставляются каждый раз: без своих организаций и
# новых репозиториев
code=$(api PATCH "/admin/users/$STUDENT_LOGIN" \
    "{\"login_name\":\"$STUDENT_LOGIN\",\"source_id\":0,\"active\":true,\"password\":\"$STUDENT_PASS\",\"must_change_password\":false,\"max_repo_creation\":0,\"allow_create_organization\":false}")
api_ok "пользователь $STUDENT_LOGIN" "$code" 200
# Пустой приватный репозиторий: студент сам зальёт туда клон шаблона
ensure "репозиторий $STUDENT_LOGIN/$REPO" "/repos/$STUDENT_LOGIN/$REPO" "/admin/users/$STUDENT_LOGIN/repos" \
    "{\"name\":\"$REPO\",\"private\":true,\"auto_init\":false,\"default_branch\":\"main\"}"

log "Готово"
echo "   Gitea:     http://<адрес ens3>:$PORT/"
echo "   шаблон:    http://<адрес ens3>:$PORT/$ORG/$REPO.git"
echo "   студент:   $STUDENT_LOGIN / $STUDENT_PASS -> http://<адрес ens3>:$PORT/$STUDENT_LOGIN/$REPO.git"
echo "   админ:     $ADMIN_FILE"
echo "   репозитории на диске: $WORK/data/gitea-repositories"
