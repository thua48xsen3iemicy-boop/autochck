#!/bin/bash
# Подготовка Gitea к лабе:
#   - админ LAB_ADMIN и его токен для автопроверки;
#   - организация LAB_ORG с публичным шаблоном LAB_REPO (история из нескольких
#     коммитов); студенты в организации не состоят, поэтому для них шаблон
#     только на чтение;
#   - учётки студентов со случайными паролями и у каждого пустой приватный
#     репозиторий LAB_REPO, создавать другие репозитории студенты не могут.
#
# Запуск:  docker exec gitea-lab init-lab
#          docker exec gitea-lab init-lab --reset student05 [student07 ...]
# Повторный запуск безопасен: существующее не трогается, новые студенты из
# списка дописываются. --reset выдаёт новые пароли указанным студентам.
#
# Результат в /data/lab (на хосте — ./data/lab):
#   accounts.txt   логин, пароль, адрес репозитория — раздать студентам
#   admin.txt      логин и пароль админа
#   token.txt      токен админа для автопроверки (API)
set -euo pipefail

LAB=/data/lab
ORG=${LAB_ORG:-course}
REPO=${LAB_REPO:-portals}
ADMIN=${LAB_ADMIN:-labadmin}
COUNT=${LAB_STUDENTS:-30}
PREFIX=${LAB_PREFIX:-student}
PASSLEN=${LAB_PASSLEN:-10}
EMAIL_DOMAIN=${LAB_EMAIL_DOMAIN:-lab.local}
TEMPLATE=/setup/portals
CONF=${GITEA_CUSTOM:-/data/gitea}/conf/app.ini
LOCAL=http://localhost:3000
API=$LOCAL/api/v1
URL=${GITEA__server__ROOT_URL:-$LOCAL/}
URL=${URL%/}

die() { echo "ОШИБКА: $*" >&2; exit 1; }
log() { echo "== $*"; }

# Каталог результата создаёт root, всё остальное — от пользователя git
if [ "$(id -u)" = 0 ]; then
    mkdir -p "$LAB"
    chown git:git "$LAB"
    chmod 700 "$LAB"
    export HOME=/data/git
    exec su-exec git "$0" "$@"
fi
[ "$(id -un)" = git ] || die "запускайте от root или git: docker exec gitea-lab init-lab"

umask 077
mkdir -p "$LAB"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Пароль без похожих символов (0/O, 1/l/I)
gen_pass() {
    head -c 512 /dev/urandom | LC_ALL=C tr -dc 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789' \
        | cut -c "1-$PASSLEN"
}

# api МЕТОД ПУТЬ [JSON] -> код ответа; тело в $TMP/body
api() {
    curl -sS -o "$TMP/body" -w '%{http_code}' -X "$1" \
        -H "Authorization: token $TOKEN" -H 'Content-Type: application/json' \
        ${3:+--data "$3"} "$API$2"
}

# api_ok ОПИСАНИЕ КОД_ОТВЕТА ДОПУСТИМЫЕ_КОДЫ...
api_ok() {
    local what=$1 code=$2; shift 2
    for c in "$@"; do [ "$code" = "$c" ] && return 0; done
    die "$what: HTTP $code: $(cat "$TMP/body")"
}

log "Жду Gitea"
for _ in $(seq 60); do
    curl -sf "$API/version" >/dev/null && break
    sleep 1
done
curl -sf "$API/version" >/dev/null || die "Gitea не отвечает на $API"

# ------------------------------------------------------------------ админ
if [ ! -f "$LAB/admin.txt" ]; then
    if gitea admin user list -c "$CONF" --admin | awk 'NR > 1 {print $2}' | grep -qx "$ADMIN"; then
        die "админ $ADMIN уже есть, но нет $LAB/admin.txt — удалите data/ или задайте другой LAB_ADMIN"
    fi
    log "Создаю админа $ADMIN"
    pass=$(gen_pass)
    gitea admin user create -c "$CONF" --admin --username "$ADMIN" --password "$pass" \
        --email "$ADMIN@$EMAIL_DOMAIN" --must-change-password=false >/dev/null
    printf '%s %s\n' "$ADMIN" "$pass" > "$LAB/admin.txt"
    rm -f "$LAB/token.txt"
fi
if [ ! -s "$LAB/token.txt" ]; then
    log "Создаю токен автопроверки"
    gitea admin user generate-access-token -c "$CONF" --username "$ADMIN" \
        --token-name "autocheck-$(date +%s)" --scopes all --raw > "$LAB/token.txt"
fi
TOKEN=$(cat "$LAB/token.txt")

# ------------------------------------------------------------------ шаблон
code=$(api GET "/orgs/$ORG")
if [ "$code" = 404 ]; then
    log "Создаю организацию $ORG"
    code=$(api POST /orgs "{\"username\":\"$ORG\",\"full_name\":\"Курс\",\"visibility\":\"public\"}")
    api_ok "организация $ORG" "$code" 201
else
    api_ok "организация $ORG" "$code" 200
fi

code=$(api GET "/repos/$ORG/$REPO")
if [ "$code" = 404 ]; then
    log "Создаю шаблон $ORG/$REPO"
    code=$(api POST "/orgs/$ORG/repos" \
        "{\"name\":\"$REPO\",\"private\":false,\"default_branch\":\"main\",\"description\":\"Шаблон: четыре портала (только чтение)\"}")
    api_ok "репозиторий $ORG/$REPO" "$code" 201
else
    api_ok "репозиторий $ORG/$REPO" "$code" 200
fi

# Флаг empty в API обновляется с задержкой, поэтому смотрим ветки напрямую
TPL_URL="http://$ADMIN:$TOKEN@localhost:3000/$ORG/$REPO.git"
if [ -z "$(git ls-remote --heads "$TPL_URL")" ]; then
    log "Заливаю содержимое шаблона"
    w=$TMP/tpl
    mkdir -p "$w"
    g() { git -C "$w" -c user.name="Курс" -c user.email="$ORG@$EMAIL_DOMAIN" "$@"; }
    g init -q -b main
    # История из нескольких коммитов: у студента она должна сохраниться
    cp -r "$TEMPLATE/README.md" "$TEMPLATE/shop" "$TEMPLATE/blog" "$w/"
    g add -A && g commit -qm "Порталы shop и blog"
    cp -r "$TEMPLATE/wiki" "$TEMPLATE/news" "$w/"
    g add -A && g commit -qm "Порталы wiki и news"
    cp -r "$TEMPLATE/nginx" "$w/"
    g add -A && g commit -qm "Конфиги nginx для порталов"
    g push -q "$TPL_URL" main 2>/dev/null
fi

# ------------------------------------------------------------------ студенты
if [ -f "$LAB/students.list" ]; then
    mapfile -t STUDENTS < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$LAB/students.list" | grep -v '^$')
else
    STUDENTS=()
    for i in $(seq 1 "$COUNT"); do STUDENTS+=("$(printf "%s%02d" "$PREFIX" "$i")"); done
fi
[ ${#STUDENTS[@]} -gt 0 ] || die "список студентов пуст"

# Уже выданные пароли
declare -A PASS
if [ -f "$LAB/accounts.txt" ]; then
    while read -r login pass _; do
        [[ -z "$login" || "$login" == \#* ]] && continue
        PASS[$login]=$pass
    done < "$LAB/accounts.txt"
fi

declare -A RESET
if [ "${1:-}" = --reset ]; then
    shift
    [ $# -gt 0 ] || die "--reset: укажите логины"
    for u in "$@"; do
        found=
        for s in "${STUDENTS[@]}"; do [ "$s" = "$u" ] && found=1; done
        [ -n "$found" ] || die "--reset: студента $u нет в списке"
        RESET[$u]=1
    done
fi

set_user_limits() {  # без своих организаций и новых репозиториев
    local code
    code=$(api PATCH "/admin/users/$1" \
        "{\"login_name\":\"$1\",\"source_id\":0,\"active\":true,\"max_repo_creation\":0,\"allow_create_organization\":false$2}")
    api_ok "пользователь $1" "$code" 200
}

for u in "${STUDENTS[@]}"; do
    [[ "$u" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "недопустимый логин: '$u'"
    code=$(api GET "/users/$u")
    if [ "$code" = 404 ]; then
        echo "   + $u"
        pass=$(gen_pass)
        code=$(api POST /admin/users \
            "{\"username\":\"$u\",\"email\":\"$u@$EMAIL_DOMAIN\",\"password\":\"$pass\",\"must_change_password\":false}")
        api_ok "пользователь $u" "$code" 201
        PASS[$u]=$pass
    else
        api_ok "пользователь $u" "$code" 200
        if [ -n "${RESET[$u]:-}" ] || [ -z "${PASS[$u]:-}" ]; then
            echo "   * $u: новый пароль"
            pass=$(gen_pass)
            set_user_limits "$u" ",\"password\":\"$pass\",\"must_change_password\":false"
            PASS[$u]=$pass
        fi
    fi

    # Пустой приватный репозиторий: студент сам зальёт туда клон шаблона
    code=$(api GET "/repos/$u/$REPO")
    if [ "$code" = 404 ]; then
        code=$(api POST "/admin/users/$u/repos" \
            "{\"name\":\"$REPO\",\"private\":true,\"auto_init\":false,\"default_branch\":\"main\"}")
        api_ok "репозиторий $u/$REPO" "$code" 201
    else
        api_ok "репозиторий $u/$REPO" "$code" 200
    fi
    set_user_limits "$u" ""
done

# ------------------------------------------------------------------ итог
{
    echo "# Gitea: $URL"
    echo "# Шаблон (только чтение): $URL/$ORG/$REPO.git"
    echo "# логин  пароль  свой репозиторий"
    for u in "${STUDENTS[@]}"; do
        printf '%s  %s  %s\n' "$u" "${PASS[$u]}" "$URL/$u/$REPO.git"
    done
} > "$LAB/accounts.txt.new"
mv "$LAB/accounts.txt.new" "$LAB/accounts.txt"

log "Готово: ${#STUDENTS[@]} студентов"
echo "   учётки:  $LAB/accounts.txt"
echo "   админ:   $LAB/admin.txt"
echo "   токен:   $LAB/token.txt"
