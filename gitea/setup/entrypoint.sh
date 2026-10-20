#!/bin/sh
# Первый запуск: без SECRET_KEY в app.ini попал бы пустой ключ, поэтому
# генерируем его до штатного entrypoint образа (он создаёт app.ini).
if [ ! -f "${GITEA_CUSTOM}/conf/app.ini" ] && [ -z "$SECRET_KEY" ]; then
    SECRET_KEY=$(gitea generate secret SECRET_KEY)
    export SECRET_KEY
fi
exec /usr/bin/entrypoint "$@"
