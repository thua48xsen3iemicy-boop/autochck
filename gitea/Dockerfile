# Gitea для лабы «git: шаблон portals -> свой репозиторий -> серверы».
# Сборка и запуск: docker compose up -d --build (см. README.md).
FROM gitea/gitea:1.24.6

# Настройки по умолчанию; адрес сервера задаётся в docker-compose.yml.
# Вход только по паролю через HTTP: SSH, регистрация, почта и внешние
# ресурсы (gravatar и т. п.) выключены.
ENV INSTALL_LOCK=true \
    DISABLE_SSH=true \
    DISABLE_REGISTRATION=true \
    REQUIRE_SIGNIN_VIEW=false \
    DB_TYPE=sqlite3 \
    GITEA__server__OFFLINE_MODE=true \
    GITEA__server__LFS_START_SERVER=false \
    GITEA__service__DEFAULT_ALLOW_CREATE_ORGANIZATION=false \
    GITEA__service__DEFAULT_KEEP_EMAIL_PRIVATE=true \
    GITEA__service__ENABLE_NOTIFY_MAIL=false \
    GITEA__mailer__ENABLED=false \
    GITEA__openid__ENABLE_OPENID_SIGNIN=false \
    GITEA__openid__ENABLE_OPENID_SIGNUP=false \
    GITEA__repository__DEFAULT_BRANCH=main \
    GITEA__repository__ENABLE_PUSH_CREATE_USER=false \
    GITEA__repository__ENABLE_PUSH_CREATE_ORG=false \
    GITEA__security__PASSWORD_COMPLEXITY=off \
    GITEA__security__MIN_PASSWORD_LENGTH=8 \
    GITEA__security__PASSWORD_CHECK_PWN=false \
    GITEA__api__ENABLE_SWAGGER=false \
    GITEA__other__SHOW_FOOTER_VERSION=false

COPY setup/portals /setup/portals
COPY setup/init-lab.sh /usr/local/bin/init-lab
COPY setup/entrypoint.sh /usr/local/bin/lab-entrypoint
RUN chmod 755 /usr/local/bin/init-lab /usr/local/bin/lab-entrypoint \
 && chmod -R a+rX /setup

ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
CMD ["/usr/bin/s6-svscan", "/etc/s6"]
