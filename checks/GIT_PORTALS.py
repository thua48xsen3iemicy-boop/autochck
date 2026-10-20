"""Лаба «git: от шаблона до серверов»: подготовка и доп. проверки.

Переименуйте файл под имя .unl лабы (KS24.unl -> KS24.py) и положите в
/pnet/checks. В description лабы — autocheck:on prepare:on.

Топология:
  Git — Debian 12 из образа с Gitea (gitea/node/install-gitea.sh), ens3 по
  DHCP; студент видит адрес в PNET и работает с Gitea со своей машины:
  шаблон course/portals (только чтение), свой пустой student/portals,
  логин student / student123;
  app1..app4 — RHEL-подобные, связность с Git есть.

Подготовка:
  - Git: имя узла, проверка, что Gitea из образа запущена и репозитории на
    месте (сам узел уже готов в образе);
  - app1..app4: имя узла, пакеты nginx и git, nginx enabled и запущен,
    пользователь deploy / deploy123 без root, пустой /var/www/portals
    (владелец nginx), sudo для deploy только на: git от имени nginx,
    ln -s / rm конфигов сайтов в conf.d, nginx -t, systemctl reload nginx.

Задание одно для всех (TASK ниже): залить шаблон в свой репозиторий,
развернуть сайты по раскладке LAYOUT клоном своего репозитория и сделать
три итерации «правка — commit — push — pull на всех app-узлах».

Проверка (только чтение):
  Git: в student/portals вся история шаблона, сверху не меньше MIN_COMMITS
  коммитов с заданным автором; на main есть правки трёх итераций.
  app1..app4: /var/www/portals — клон student/portals (не шаблона), HEAD =
  main из Gitea, git status чистый, всё принадлежит nginx; в nginx включены
  ровно сайты из LAYOUT; curl на самом узле отдаёт актуальные страницы.
  Пароль в адресе origin — замечание.

Оценка только по этим пунктам (ONLY_EXTRA, KEEP пуст: имена узлов ставит
подготовка).
"""

import asyncio
import base64
import re
import shlex

ONLY_EXTRA = True
KEEP = []

# ------------------------------------------------------------------ параметры
GIT_NODE = 'Git'
APP_NODES = ['app1', 'app2', 'app3', 'app4']
# Какие сайты на каком узле
LAYOUT = {
    'app1': ['shop', 'blog'],
    'app2': ['wiki'],
    'app3': ['news'],
    'app4': ['news'],
}
SITE_DOMAIN = 'lab'                  # shop -> shop.lab
SITE_TITLES = {
    'shop': 'Магазин посуды',
    'blog': 'Блог разработчика',
    'wiki': 'Вики по Linux',
    'news': 'Новости колледжа',
}

GITEA_PORT = 3000
GITEA_REPOS = '/var/lib/gitea/data/gitea-repositories'
TEMPLATE_REPO = 'course/portals'
STUDENT_REPO = 'student/portals'
STUDENT_LOGIN, STUDENT_PASS = 'student', 'student123'   # заданы в образе Git
BRANCH = 'main'
MIN_COMMITS = 3                      # коммитов студента поверх шаблона

CLONE_DIR = '/var/www/portals'
WEB_USER = 'nginx'
CONF_DIR = '/etc/nginx/conf.d'
DEPLOY_USER, DEPLOY_PASS = 'deploy', 'deploy123'
PACKAGES = ['nginx', 'git']
SUDOERS_FILE = '/etc/sudoers.d/deploy-portals'

POINTS = {
    'repo': 1,       # шаблон в своём репозитории с историей
    'commits': 1,    # коммиты студента
    'it1': 1,
    'it2': 1,
    'it3': 1,
    'clone': 1,      # за узел
    'head': 1,       # за узел
    'clean': 1,      # за узел
    'sites': 1,      # за узел
    'pages': 1,      # за сайт на узле
}

LABELS = {
    'repo': 'Шаблон залит в свой репозиторий с историей',
    'commits': f'Свои коммиты: не меньше {MIN_COMMITS}, автор задан',
    'it1': 'Итерация 1: новая цена кружки',
    'it2': 'Итерация 2: страница экзамена',
    'it3': 'Итерация 3: удалена страница scp',
    'clone': 'Серверы: клон своего репозитория',
    'head': 'Серверы: последняя версия (git pull)',
    'clean': 'Серверы: без ручных правок, владелец nginx',
    'sites': 'Серверы: включены нужные сайты',
    'pages': 'Сайты отвечают актуальными страницами',
}

TASK = f'''Gitea — на узле {GIT_NODE}: http://<адрес {GIT_NODE}>:{GITEA_PORT} (адрес ens3 виден в PNET). \
Логин {STUDENT_LOGIN}, пароль {STUDENT_PASS}.
На app1–app4 входите как {DEPLOY_USER} / {DEPLOY_PASS}. Root не нужен: разрешённые команды покажет sudo -l.

1. На своей машине склонируйте шаблон {TEMPLATE_REPO} и залейте его в свой репозиторий {STUDENT_REPO}:
git clone http://<адрес {GIT_NODE}>:{GITEA_PORT}/{TEMPLATE_REPO}.git
cd portals
git remote rename origin upstream
git remote add origin http://<адрес {GIT_NODE}>:{GITEA_PORT}/{STUDENT_REPO}.git
git push -u origin {BRANCH}
Перед своими коммитами задайте git config user.name и user.email.

2. Разверните сайты из своего репозитория: app1 — shop и blog, app2 — wiki, app3 и app4 — news. На каждом узле:
sudo -u {WEB_USER} git clone http://<адрес {GIT_NODE}>:{GITEA_PORT}/{STUDENT_REPO}.git {CLONE_DIR}
sudo ln -s {CLONE_DIR}/nginx/<сайт>.conf {CONF_DIR}/<сайт>.conf — для каждого сайта узла
sudo nginx -t && sudo systemctl reload nginx
Проверка: curl -H "Host: <сайт>.{SITE_DOMAIN}" http://127.0.0.1/

3. Итерация 1. В shop/catalog/cups.html цена красной кружки — 500 ₽ вместо 450 ₽.

4. Итерация 2. Добавьте страницу news/study/exam.html с текстом «Экзамен по Linux — 25 декабря» \
и ссылку на неё на главной news (news/index.html).

5. Итерация 3. Удалите wiki/commands/scp.html (git rm) и ссылку на неё в wiki/commands/index.html.

После каждой итерации: commit, push и обновление всех серверов app1–app4:
sudo -u {WEB_USER} git -C {CLONE_DIR} pull

Файлы на серверах руками не правьте: всё только через git.'''


# ------------------------------------------------------------------ итерации
def it1_problem(text):
    """Цена красной кружки 500 вместо 450."""
    line = next((l for l in text.split('\n') if 'Красная кружка' in l), None)
    if line is None:
        return 'нет строки про красную кружку'
    if '500' not in line or '450' in line:
        return f'цена не изменена: «{strip_tags(line)[:80]}»'
    return None


def it2_page_problem(text):
    if 'Экзамен по Linux' not in text or '25 декабря' not in text:
        return 'нет текста «Экзамен по Linux — 25 декабря»'
    return None


def it2_link_problem(text):
    return None if 'study/exam.html' in text else 'на главной news нет ссылки на study/exam.html'


def it3_link_problem(text):
    return 'осталась ссылка на scp.html' if 'scp.html' in text else None


# Файлы, которые читаются из репозитория на Git
REPO_FILES = ['shop/catalog/cups.html', 'news/study/exam.html', 'news/index.html',
              'wiki/commands/index.html', 'wiki/commands/scp.html']

# Страницы, которые запрашиваются на узлах: сайт -> [(URL, проверка ответа)].
# Проверка: (код, текст) -> None или описание проблемы
def code_text(code):
    return 'нет ответа' if code in ('', '000') else f'код {code}'


def title_check(site):
    def check(code, text):
        if code != '200':
            return code_text(code)
        return None if SITE_TITLES[site] in text else 'отдаётся не этот сайт'
    return check


def page_check(problem):
    def check(code, text):
        if code != '200':
            return 'нет страницы' if code == '404' else code_text(code)
        return problem(text)
    return check


def gone_check(code, _text):
    if code == '404':
        return None
    return 'страница ещё отдаётся' if code == '200' else code_text(code)


PAGES = {
    'shop': [('/', title_check('shop')), ('/catalog/cups.html', page_check(it1_problem))],
    'blog': [('/', title_check('blog'))],
    'wiki': [('/', title_check('wiki')), ('/commands/scp.html', gone_check)],
    'news': [('/', title_check('news')), ('/study/exam.html', page_check(it2_page_problem))],
}


def strip_tags(text):
    return re.sub(r'<[^>]*>', '', text).strip()


def host(site):
    return f'{site}.{SITE_DOMAIN}'


# ------------------------------------------------------------------ подготовка
def sudoers_text():
    sites = sorted(SITE_TITLES)
    ln = [f'/usr/bin/ln -s {CLONE_DIR}/nginx/{s}.conf {CONF_DIR}/{s}.conf' for s in sites]
    rm = [f'/usr/bin/rm {CONF_DIR}/{s}.conf' for s in sites]
    return '\n'.join([
        f'# Лаба с git: {DEPLOY_USER} работает без root, только эти команды',
        'Cmnd_Alias PORTALS_SITES = ' + ', '.join(ln + rm),
        'Cmnd_Alias PORTALS_NGINX = /usr/sbin/nginx -t, /usr/bin/systemctl reload nginx',
        f'{DEPLOY_USER} ALL=({WEB_USER}) NOPASSWD: /usr/bin/git',
        f'{DEPLOY_USER} ALL=(root) NOPASSWD: PORTALS_SITES, PORTALS_NGINX',
        '',
    ])


def app_prepare_script():
    q = shlex.quote
    b64 = base64.b64encode(sudoers_text().encode('utf-8')).decode('ascii')
    pkgs = ' '.join(q(p) for p in PACKAGES)
    return '\n'.join([
        'set -e',
        'need=',
        f'for p in {pkgs}; do',
        '  rpm -q "$p" >/dev/null 2>&1 || dpkg -s "$p" 2>/dev/null | grep -q "^Status: install ok installed" '
        '|| need="$need $p"',
        'done',
        'if [ -n "$need" ]; then',
        '  if command -v dnf >/dev/null; then dnf -y -q install $need',
        '  else DEBIAN_FRONTEND=noninteractive apt-get install -y -q $need; fi',
        'fi',
        'systemctl enable --now nginx >/dev/null 2>&1',
        f'id {DEPLOY_USER} >/dev/null 2>&1 || useradd -m -s /bin/bash {DEPLOY_USER}',
        f"echo {q(f'{DEPLOY_USER}:{DEPLOY_PASS}')} | chpasswd",
        f'install -d -m 755 {q(posix_dir(CLONE_DIR))}',
        f'[ -e {q(CLONE_DIR)} ] || install -d -o {WEB_USER} -g {WEB_USER} -m 755 {q(CLONE_DIR)}',
        f'if command -v restorecon >/dev/null; then restorecon -R {q(posix_dir(CLONE_DIR))}; fi',
        't=$(mktemp)',
        f'printf %s {q(b64)} | base64 -d > "$t"',
        'visudo -cqf "$t"',
        f'install -m 440 "$t" {q(SUDOERS_FILE)}',
        'rm -f "$t"',
    ])


def git_prepare_script():
    q = shlex.quote
    repos = ' '.join(q(f'{GITEA_REPOS}/{r}.git') for r in (TEMPLATE_REPO, STUDENT_REPO))
    return '\n'.join([
        'systemctl is-active --quiet gitea || systemctl restart gitea',
        f'for i in $(seq 30); do curl -sf http://localhost:{GITEA_PORT}/api/v1/version >/dev/null && break; sleep 1; done',
        f'curl -sf http://localhost:{GITEA_PORT}/api/v1/version >/dev/null '
        '|| { echo "Gitea не запущена (journalctl -u gitea)" >&2; exit 1; }',
        f'for r in {repos}; do',
        '  [ -d "$r" ] || { echo "нет репозитория $r: узел не из образа с Gitea (install-gitea.sh)" >&2; exit 1; }',
        'done',
    ])


def posix_dir(path):
    return path.rsplit('/', 1)[0] or '/'


async def prepare_node(ctx, node):
    await ctx.set_hostname(node, node)
    if node == GIT_NODE:
        await ctx.shell(node, git_prepare_script(), step='Gitea')
    else:
        await ctx.shell(node, app_prepare_script(), step='nginx, git, пользователь deploy и sudo')


async def prepare(ctx):
    for node in [GIT_NODE] + APP_NODES:
        if node not in ctx.nodes:
            raise PrepareError(node, 'топология', 'такого узла нет в лабе', teacher=True)
    nodes = [n for n in [GIT_NODE] + APP_NODES if not ctx.skipped(n)]
    # Узлы параллельно: установка пакетов на каждом занимает время
    results = await asyncio.gather(*(prepare_node(ctx, n) for n in nodes), return_exceptions=True)
    for res in results:
        if isinstance(res, BaseException):
            raise res


# ------------------------------------------------------------------ скрипты проверки
def show_file(marker, git_dir, rev):
    """Секция с base64 файла из репозитория; MISSING — файла нет."""
    q = shlex.quote
    return (f"echo {q('==' + marker)}; if git --git-dir={git_dir} cat-file -e {q(rev)} 2>/dev/null; "
            f"then printf 'B64:'; git --git-dir={git_dir} show {q(rev)} | base64 -w0; echo; else echo MISSING; fi")


def git_script():
    q = shlex.quote
    s = q(f'{GITEA_REPOS}/{STUDENT_REPO}.git')
    t = q(f'{GITEA_REPOS}/{TEMPLATE_REPO}.git')
    b = q(BRANCH)
    lines = [
        'echo ==ACTIVE; systemctl is-active gitea 2>/dev/null',
        f'tpl=$(git --git-dir={t} rev-parse -q --verify {b} 2>/dev/null)',
        'echo ==TPL; echo "$tpl"',
        f'echo ==MAIN; git --git-dir={s} rev-parse -q --verify {b} 2>/dev/null',
        f'echo ==ANCESTOR; [ -n "$tpl" ] && git --git-dir={s} merge-base --is-ancestor "$tpl" {b} 2>/dev/null '
        '&& echo YES',
        f'echo ==LOG; [ -n "$tpl" ] && git --git-dir={s} log --format=\'%H%x09%an%x09%ae\' "$tpl..{BRANCH}" '
        '2>/dev/null | head -n 100',
    ]
    for f in REPO_FILES:
        lines.append(show_file('FILE ' + f, s, f'{BRANCH}:{f}'))
    lines.append('echo ==END')
    return '\n'.join(lines)


def app_script(node):
    q = shlex.quote
    d = q(CLONE_DIR)
    g = f'runuser -u {WEB_USER} -- env HOME=/tmp git --no-optional-locks -C {d}'
    lines = [
        'echo ==ACTIVE; systemctl is-active nginx 2>/dev/null',
        # имена из server_name всех подключённых конфигов
        "echo ==NAMES; nginx -T 2>/dev/null | sed 's/#.*//' | grep -oE '(^|[[:space:];{])server_name[[:space:]][^;]*' "
        "| sed -E 's/.*server_name[[:space:]]+//' | tr -s ' \\t' '\\n\\n'",
        f'echo ==REPO; [ -d {d}/.git ] && echo YES',
        f'echo ==ORIGIN; {g} config --get remote.origin.url 2>/dev/null',
        f'echo ==HEAD; {g} rev-parse HEAD 2>/dev/null',
        f'echo ==STATUS; {g} status --porcelain 2>&1 | head -n 20',
        f'echo ==OWNER; find {d} ! -user {WEB_USER} 2>/dev/null | head -n 5',
        'echo ==CURL',
    ]
    for site in LAYOUT[node]:
        for i, (url, _check) in enumerate(PAGES[site]):
            lines.append(
                f"rm -f /tmp/.portals_page; b=$(curl -s --noproxy '*' -m 5 -H {q('Host: ' + host(site))} -o /tmp/.portals_page "
                f"-w '%{{http_code}}' {q('http://127.0.0.1' + url)} 2>/dev/null); "
                f"echo {q(site)} {i} \"$b\" $(base64 -w0 /tmp/.portals_page 2>/dev/null)")
    lines.append('rm -f /tmp/.portals_page; echo ==END')
    return '\n'.join(lines)


# ------------------------------------------------------------------ разбор вывода
def sections(out):
    res, cur = {}, None
    for line in out.split('\n'):
        line = line.rstrip('\r')
        if line.startswith('=='):
            cur = line[2:].strip()
            res[cur] = []
        elif cur is not None:
            res[cur].append(line)
    return res


def first(lines):
    return next((l.strip() for l in lines if l.strip()), '')


def b64_text(lines):
    """Текст из секции show_file; None — файла нет."""
    line = first(lines)
    if not line.startswith('B64:'):
        return None
    try:
        return base64.b64decode(line[4:]).decode('utf-8', errors='replace')
    except ValueError:
        return None


def responded(out):
    return bool(out) and not out.startswith('NONE') and '==END' in out


class Score:
    def __init__(self):
        self.got = dict.fromkeys(POINTS, 0)
        self.max = dict.fromkeys(POINTS, 0)

    def add(self, key, good):
        self.max[key] += POINTS[key]
        if good:
            self.got[key] += POINTS[key]


# ------------------------------------------------------------------ проверки
def check_git(out, score, errors):
    """Репозиторий студента на Git. Возвращает SHA его main (или None)."""
    keys = ('repo', 'commits', 'it1', 'it2', 'it3')
    if not responded(out):
        for k in keys:
            score.add(k, False)
        errors.append(f'{GIT_NODE}: узел не ответил на проверку')
        return None
    s = sections(out)
    if first(s.get('ACTIVE', [])) != 'active':
        errors.append(f'{GIT_NODE}: Gitea не запущена')
    main = first(s.get('MAIN', []))
    if not first(s.get('TPL', [])):
        for k in keys:
            score.add(k, False)
        errors.append(f'{GIT_NODE}: нет шаблона {TEMPLATE_REPO} — сообщите преподавателю')
        return main or None
    if not main:
        for k in keys:
            score.add(k, False)
        errors.append(f'{STUDENT_REPO}: репозиторий пуст — шаблон в него не залит (git push)')
        return None

    ancestor = first(s.get('ANCESTOR', [])) == 'YES'
    score.add('repo', ancestor)
    if not ancestor:
        errors.append(f'{STUDENT_REPO}: в ветке {BRANCH} нет истории шаблона — нужно клонировать '
                      f'{TEMPLATE_REPO} и залить его, а не создавать репозиторий заново')

    commits = [l.split('\t') for l in s.get('LOG', []) if l.strip()]
    bad_author = [c for c in commits if len(c) < 3 or not c[1].strip() or c[1].strip() == 'root'
                  or '@' not in c[2] or c[2].endswith('(none)')]
    good = ancestor and len(commits) >= MIN_COMMITS and not bad_author
    score.add('commits', good)
    if ancestor and len(commits) < MIN_COMMITS:
        errors.append(f'{STUDENT_REPO}: своих коммитов поверх шаблона {len(commits)}, '
                      f'нужно не меньше {MIN_COMMITS}')
    if bad_author:
        errors.append(f'{STUDENT_REPO}: у коммитов не задан автор (git config user.name и user.email)')

    files = {f: b64_text(s.get('FILE ' + f, [])) for f in REPO_FILES}
    cups = files['shop/catalog/cups.html']
    p = 'нет файла' if cups is None else it1_problem(cups)
    score.add('it1', p is None)
    if p:
        errors.append(f'{STUDENT_REPO}: shop/catalog/cups.html — {p}')

    exam, news = files['news/study/exam.html'], files['news/index.html']
    probs = ['нет страницы news/study/exam.html' if exam is None else it2_page_problem(exam),
             'нет news/index.html' if news is None else it2_link_problem(news)]
    probs = [x for x in probs if x]
    score.add('it2', not probs)
    if probs:
        errors.append(f'{STUDENT_REPO}: итерация 2 — {"; ".join(probs)}')

    probs = []
    if files['wiki/commands/scp.html'] is not None:
        probs.append('файл wiki/commands/scp.html не удалён')
    idx = files['wiki/commands/index.html']
    if idx is not None and it3_link_problem(idx):
        probs.append('в wiki/commands/index.html ' + it3_link_problem(idx))
    score.add('it3', not probs)
    if probs:
        errors.append(f'{STUDENT_REPO}: итерация 3 — {"; ".join(probs)}')
    return main


ORIGIN_RE = re.compile(r'^(?:https?://(?:([^/@]*)@)?[^/]+/|[^:/]+:)(.+?)(?:\.git)?/*$')


def check_app(node, out, main, score, errors, remarks):
    sites = LAYOUT[node]
    if not responded(out):
        for k in ('clone', 'head', 'clean', 'sites'):
            score.add(k, False)
        for _site in sites:
            score.add('pages', False)
        errors.append(f'{node}: узел не ответил на проверку')
        return
    s = sections(out)

    # клон своего репозитория
    origin = first(s.get('ORIGIN', []))
    is_repo = first(s.get('REPO', [])) == 'YES'
    m = ORIGIN_RE.match(origin)
    path = m.group(2) if m else ''
    good = is_repo and path == STUDENT_REPO
    score.add('clone', good)
    if not is_repo:
        errors.append(f'{node}: {CLONE_DIR} — не git-клон (sudo -u {WEB_USER} git clone …)')
    elif path == TEMPLATE_REPO:
        errors.append(f'{node}: в {CLONE_DIR} склонирован шаблон {TEMPLATE_REPO}, а нужен свой {STUDENT_REPO}')
    elif not good:
        errors.append(f'{node}: origin в {CLONE_DIR} — «{origin or "нет"}», а должен быть {STUDENT_REPO}')
    if m and m.group(1) and ':' in m.group(1):
        remarks.append(f'{node}: пароль записан в адрес origin — он лежит открытым текстом в .git/config')

    # последняя версия
    head = first(s.get('HEAD', []))
    good = good and bool(main) and head == main
    score.add('head', good)
    if is_repo and path == STUDENT_REPO and main and head and head != main:
        errors.append(f'{node}: в {CLONE_DIR} не последняя версия из {STUDENT_REPO} (git pull)')

    # без ручных правок
    status = [l for l in s.get('STATUS', []) if l.strip()]
    owners = [l for l in s.get('OWNER', []) if l.strip()]
    good = is_repo and not status and not owners
    score.add('clean', good)
    if is_repo and status:
        errors.append(f'{node}: в {CLONE_DIR} есть изменения мимо git: {", ".join(x.strip() for x in status[:3])}')
    if is_repo and owners:
        errors.append(f'{node}: в {CLONE_DIR} есть файлы не пользователя {WEB_USER}: {", ".join(owners[:3])}')

    # включённые сайты
    active = first(s.get('ACTIVE', [])) == 'active'
    names = {n.strip().lower() for n in s.get('NAMES', []) if n.strip().endswith('.' + SITE_DOMAIN)}
    want = {host(x) for x in sites}
    missing, extra = sorted(want - names), sorted(names - want)
    score.add('sites', active and not missing and not extra)
    if not active:
        errors.append(f'{node}: nginx не запущен')
    if missing:
        errors.append(f'{node}: не включены сайты: {", ".join(missing)}')
    if extra:
        errors.append(f'{node}: лишние сайты (их место на других узлах): {", ".join(extra)}')

    # страницы
    got = {}
    for line in s.get('CURL', []):
        parts = line.split(' ')
        if len(parts) >= 3 and parts[1].isdigit():
            got[(parts[0], int(parts[1]))] = (parts[2], parts[3] if len(parts) > 3 else '')
    for site in sites:
        probs = []
        for i, (url, check) in enumerate(PAGES[site]):
            code, body = got.get((site, i), ('', ''))
            try:
                text = base64.b64decode(body).decode('utf-8', errors='replace')
            except ValueError:
                text = ''
            p = check(code, text)
            if p:
                probs.append(f'http://{host(site)}{url} — {p}')
        score.add('pages', not probs)
        if probs:
            errors.append(f'{node}: ' + '; '.join(probs))


async def check(ctx):
    outs = await asyncio.gather(ctx.run(GIT_NODE, git_script()),
                                *(ctx.run(node, app_script(node)) for node in APP_NODES))
    score, errors, remarks = Score(), [], []
    main = check_git(outs[0], score, errors)
    for node, out in zip(APP_NODES, outs[1:]):
        check_app(node, out, main, score, errors, remarks)
    for e in errors:
        ctx.error(e)
    for r in remarks:
        ctx.error(f'Замечание: {r}')
    for key in POINTS:
        ctx.add_check(LABELS[key], score.got[key], score.max[key])
