# Gitea внутри лабы: образ узла git

Gitea ставится в образ узла `git` (Debian 12) один раз. После этого в каждой лабе у студента свой экземпляр Gitea, полностью готовый к работе: подготовка лабы для этого узла не нужна, а вайп узла возвращает Gitea в чистое состояние.

Что уже есть в образе:

| Что | Значение |
|---|---|
| Адрес | `http://<адрес ens3>:3000/`, адрес выдаёт DHCP, студент видит его в PNET |
| Шаблон | `course/portals`: открыт на чтение, `push` студента получит отказ |
| Студент | `student` / `student123`, одинаковые во всех лабах |
| Репозиторий студента | `student/portals`: пустой, приватный; другие репозитории и организации студент создавать не может |
| Админ | `labadmin`, пароль случайный, лежит в `/root/gitea-admin.txt` |
| Репозитории на диске | `/var/lib/gitea/data/gitea-repositories/<владелец>/<имя>.git` |

Вход только по паролю через HTTP: SSH, регистрация и почта выключены.

## Как собрать образ

1. Положите на свой веб-сервер два файла:
   - `gitea-1.24.6-linux-amd64` с https://dl.gitea.com/gitea/1.24.6/ (sha256 скрипт проверит сам);
   - `portals.tar.gz` из этого репозитория: `tar czf portals.tar.gz -C gitea/setup portals`.
2. На шаблонной ВМ с Debian 12 от root:
   ```
   BASE_URL=http://<веб-сервер>/<каталог> bash install-gitea.sh
   ```
   Пакеты `git`, `curl` и `qemu-guest-agent` скрипт поставит через apt, если их нет.
3. Выключите ВМ и сохраните образ.

Логин и пароль студента, порт и прочее меняются переменными в начале скрипта, например `STUDENT_PASS=... bash install-gitea.sh`. Повторный запуск безопасен.

## Как проверка читает репозитории

Через QGA от root, прямо с диска, без API:
```
git --git-dir=/var/lib/gitea/data/gitea-repositories/student/portals.git log main
git --git-dir=/var/lib/gitea/data/gitea-repositories/course/portals.git rev-parse main
```
