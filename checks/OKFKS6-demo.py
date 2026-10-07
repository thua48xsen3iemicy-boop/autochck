"""Доп. проверки лабы OKFKS6-demo: два name-based сайта nginx на каждом appN.

Узел R (Linux с curl) — точка входа студента:
  - 12 имён (appN и сайты appN) разрешаются в адрес appN, и записи есть в
    /etc/hosts;
  - в /etc/hosts нет имён с разными адресами, localhost не испорчен;
  - все URL сайтов отдают 200 и тело, совпадающее с эталоном (запрос по
    имени через /etc/hosts, без --resolve и без прокси).
Узлы app1..app4:
  - установлены пакеты PACKAGES, nginx enabled и active, `nginx -t` проходит,
    nginx.conf подключает conf.d (изменение nginx.conf — только замечание);
  - конфиг каждого сайта в CONF_DIR/<сайт>.conf: ровно один server,
    server_name = имя сайта, root и index по эталону, явный listen 80;
  - файлы сайтов существуют, содержимое — две строки: путь на сервере и путь
    в URL (пробелы в конце строк и финальный перевод строки не важны);
  - в root сайтов нет ничего, кроме файлов эталона и их каталогов.

Оценка только по этим пунктам и Hostnames (ONLY_EXTRA). Если на каком-то
app-узле нет KEY_PACKAGE (nginx), все пункты — 0 (см. KEY_PACKAGE).
На сервере лежит в /pnet/checks/OKFKS6-demo.py.
"""

import asyncio
import base64
import re
import shlex

ONLY_EXTRA = True

# ------------------------------------------------------------------ эталон
R_NODE = 'R'
APP_IPS = {'app1': '10.0.1.1', 'app2': '10.0.1.2', 'app3': '10.0.1.3', 'app4': '10.0.1.4'}
PACKAGES = ['nginx', 'tree']
CONF_DIR = '/etc/nginx/conf.d'
REQUIRE_LISTEN = True        # listen 80 должен быть указан явно
# Ключевой пакет: если его нет хотя бы на одном app-узле (или узел не ответил
# и проверить нельзя), все пункты лабы — 0, остальное не засчитывается
KEY_PACKAGE = 'nginx'

# сайт: (узел, root, индексный файл)
SITES = {
    'app1-first.lab':  ('app1', '/var/www/app1-first', 'index.html'),
    'app1-second.lab': ('app1', '/var/www/app1-second/public', 'index.html'),
    'app2-first.lab':  ('app2', '/srv/web/app2/first', 'index.html'),
    'app2-second.lab': ('app2', '/srv/web/app2/second/html', 'main.html'),
    'app3-first.lab':  ('app3', '/opt/sites/first/www', 'index.html'),
    'app3-second.lab': ('app3', '/opt/sites/second', 'home.html'),
    'app4-first.lab':  ('app4', '/data/www/app4-first', 'index.html'),
    'app4-second.lab': ('app4', '/usr/share/nginx/app4-second', 'index.html'),
}

# пути в URL для каждого сайта; '/' — индексный файл
URLS = {
    'app1-first.lab':  ['/', '/about.html'],
    'app1-second.lab': ['/', '/news/today.html'],
    'app2-first.lab':  ['/', '/docs/manual.html'],
    'app2-second.lab': ['/', '/contacts/phone.html'],
    'app3-first.lab':  ['/', '/catalog/books/list.html'],
    'app3-second.lab': ['/', '/help.txt'],
    'app4-first.lab':  ['/', '/2026/10/report.html'],
    'app4-second.lab': ['/', '/a/b/c/deep.html'],
}

# Баллы за единицу пункта (имя, узел, пакет, сайт, файл или URL)
POINTS = {
    'resolve': 1,      # за каждое имя на R
    'hosts_ok': 1,     # /etc/hosts на R в целом
    'pkg': 1,          # за пакет на узле
    'enabled': 1,
    'active': 1,
    'nginx_t': 1,
    'nginx_conf': 1,   # nginx.conf подключает conf.d
    'site_conf': 1,    # за сайт
    'site_files': 1,   # за файл
    'site_extra': 1,   # за сайт: в root нет лишнего
    'curl': 1,         # за URL
}

LABELS = {
    'resolve': 'R: имена разрешаются через /etc/hosts',
    'hosts_ok': 'R: /etc/hosts без конфликтов, localhost цел',
    'pkg': 'Пакеты ' + ' и '.join(PACKAGES),
    'enabled': 'nginx в автозагрузке',
    'active': 'nginx запущен',
    'nginx_t': 'Конфигурация nginx валидна (nginx -t)',
    'nginx_conf': 'nginx.conf подключает conf.d',
    'site_conf': 'Конфиги сайтов',
    'site_files': 'Файлы сайтов',
    'site_extra': 'Нет лишнего в root сайтов',
    'curl': 'Сайты отвечают с R',
}


# ------------------------------------------------------------------ эталон: производные
def node_names(node):
    """Имена, которые на R должны разрешаться в адрес узла."""
    return [node] + [s for s, (n, _r, _i) in SITES.items() if n == node]


def file_path(site, url):
    _node, root, index = SITES[site]
    return f'{root}/{index}' if url == '/' else root + url


def expected_lines(site, url):
    return [file_path(site, url), url]


def expected_tree(site):
    """Пути (относительно root), которые допустимы в root сайта."""
    _node, root, _index = SITES[site]
    allowed = set()
    for url in URLS[site]:
        rel = file_path(site, url)[len(root) + 1:]
        parts = rel.split('/')
        for i in range(1, len(parts) + 1):
            allowed.add('/'.join(parts[:i]))
    return allowed


def norm_lines(data):
    """Содержимое файла/ответа -> строки без хвостовых пробелов и без одного
    финального перевода строки."""
    text = data.decode('utf-8', errors='replace')
    if text.endswith('\n'):
        text = text[:-1]
    return [line.rstrip(' \t\r') for line in text.split('\n')]


def content_problem(data, expected):
    """None, если содержимое по эталону, иначе краткое описание отличия."""
    got = norm_lines(data)
    if got == expected:
        return None
    if len(got) != len(expected):
        return f'должно быть {len(expected)} строки, а не {len(got)}'
    for i, (g, e) in enumerate(zip(got, expected), 1):
        if g != e:
            return f'строка {i}: «{g[:80]}»'
    return 'не совпадает с эталоном'


# ------------------------------------------------------------------ скрипты узлов
def show_b64(marker, path):
    q = shlex.quote
    return (f"echo {q('==' + marker)}; if [ -f {q(path)} ]; then printf 'B64:'; "
            f"base64 -w0 {q(path)}; echo; else echo MISSING; fi")


def app_script(node):
    q = shlex.quote
    lines = ['echo ==PKG']
    for p in PACKAGES:
        lines.append(f"if rpm -q {q(p)} >/dev/null 2>&1 || dpkg -s {q(p)} 2>/dev/null | "
                     f"grep -q '^Status: install ok installed'; then echo {q(p)} OK; else echo {q(p)} NO; fi")
    lines += [
        'echo ==ENABLED; systemctl is-enabled nginx 2>/dev/null',
        'echo ==ACTIVE; systemctl is-active nginx 2>/dev/null',
        'echo ==NGINXT; if nginx -t >/dev/null 2>&1; then echo OK; else nginx -t 2>&1 | tail -n 3; fi',
        "echo ==NGINXCONF; grep -Eq '^[[:space:]]*include[[:space:]]+(/etc/nginx/)?conf\\.d/\\*\\.conf[[:space:]]*;' "
        "/etc/nginx/nginx.conf 2>/dev/null && echo INCLUDE; "
        "rpm -V nginx 2>/dev/null | grep -q ' /etc/nginx/nginx.conf$' && echo MODIFIED",
    ]
    for site, (n, root, _index) in SITES.items():
        if n != node:
            continue
        lines.append(show_b64('CONF ' + site, f'{CONF_DIR}/{site}.conf'))
        lines.append(f"echo {q('==TREE ' + site)}; [ -d {q(root)} ] && echo ROOTOK && "
                     f"find {q(root)} -mindepth 1 -printf '%P\\n'")
        for url in URLS[site]:
            lines.append(show_b64('FILE ' + file_path(site, url), file_path(site, url)))
    lines.append('echo ==END')
    return '\n'.join(lines)


def all_urls():
    return [(site, url, f'http://{site}{url}') for site in SITES for url in URLS[site]]


def r_script():
    q = shlex.quote
    lines = ['echo ==GETENT']
    for node in APP_IPS:
        for name in node_names(node):
            lines.append(f"echo {q(name)} $(getent ahostsv4 {q(name)} 2>/dev/null | awk 'NR==1{{print $1}}')")
    lines.append('echo ==HOSTS; base64 -w0 /etc/hosts 2>/dev/null; echo')
    # Запросы параллельно: последовательные таймауты не уложились бы в лимит qga
    lines.append('d=$(mktemp -d)')
    for i, (_site, _url, full) in enumerate(all_urls()):
        lines.append(f"curl -s --noproxy '*' --connect-timeout 2 -m 4 -o \"$d/{i}\" "
                     f"-w '%{{http_code}}' {q(full)} > \"$d/{i}.code\" 2>/dev/null &")
    lines.append('wait')
    lines.append('echo ==CURL')
    for i, _ in enumerate(all_urls()):
        lines.append(f"echo {i} $(cat \"$d/{i}.code\" 2>/dev/null) $(base64 -w0 \"$d/{i}\" 2>/dev/null)")
    lines.append('rm -rf "$d"; echo ==END')
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


def b64_value(lines):
    """Содержимое файла из секции show_b64; None — файла нет."""
    first = next((l for l in lines if l), '')
    if not first.startswith('B64:'):
        return None
    try:
        return base64.b64decode(first[4:])
    except ValueError:
        return None


def responded(out):
    return bool(out) and not out.startswith('NONE') and '==END' in out


# ------------------------------------------------------------------ nginx-конфиг
NGINX_LOG_PREFIX = re.compile(r'^(?:\S+ \S+ |nginx: )\[(\w+)\] (?:\d+#\d+: )?')
TOKEN_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};"\']+')


def parse_nginx(text):
    """Конфиг nginx -> [(директива, [аргументы], [вложенный блок] | None)]."""
    toks = []
    for line in text.split('\n'):
        for m in TOKEN_RE.finditer(line):
            t = m.group(0)
            if t.startswith('#'):
                break
            toks.append(t[1:-1] if t[0] in '"\'' and len(t) > 1 else t)

    def block(i):
        items, args = [], []
        while i < len(toks):
            t = toks[i]
            if t == ';':
                if args:
                    items.append((args[0], args[1:], None))
                args = []
                i += 1
            elif t == '{':
                sub, i = block(i + 1)
                items.append((args[0] if args else '', args[1:], sub))
                args = []
            elif t == '}':
                return items, i + 1
            else:
                args.append(t)
                i += 1
        return items, i

    items, _ = block(0)
    return items


def directives(block, name):
    return [args for n, args, sub in block if n == name and sub is None]


def listen_port(arg):
    if arg.isdigit():
        return arg
    if ':' in arg:
        return arg.rsplit(':', 1)[1]
    return '80'    # только адрес — порт по умолчанию


def site_conf_problems(site, text):
    _node, root, index = SITES[site]
    servers = [sub for n, _a, sub in parse_nginx(text) if n == 'server' and sub is not None]
    if len(servers) != 1:
        return [f'в файле должен быть ровно один блок server, найдено {len(servers)}']
    srv = servers[0]
    bad = []
    names = [x.lower() for args in directives(srv, 'server_name') for x in args]
    if names != [site]:
        bad.append('server_name')
    loc = next((sub for n, a, sub in srv if n == 'location' and sub is not None and a == ['/']), None)
    roots = (loc is not None and directives(loc, 'root')) or directives(srv, 'root')
    if not roots or not roots[-1] or roots[-1][0].rstrip('/') != root.rstrip('/'):
        bad.append('root')
    indexes = (loc is not None and directives(loc, 'index')) or directives(srv, 'index')
    if index not in ([x for args in indexes for x in args] if indexes else ['index.html']):
        bad.append('index')
    ports = [listen_port(args[0]) for args in directives(srv, 'listen') if args]
    if (REQUIRE_LISTEN and not ports) or any(p != '80' for p in ports):
        bad.append('listen 80')
    return bad


# ------------------------------------------------------------------ проверки
class Score:
    def __init__(self):
        self.got = dict.fromkeys(POINTS, 0)
        self.max = dict.fromkeys(POINTS, 0)

    def add(self, key, good):
        self.max[key] += POINTS[key]
        if good:
            self.got[key] += POINTS[key]


def check_app(node, out, score, errors, remarks):
    sites = [s for s, (n, _r, _i) in SITES.items() if n == node]
    if not responded(out):
        for _p in PACKAGES:
            score.add('pkg', False)
        for key in ('enabled', 'active', 'nginx_t', 'nginx_conf'):
            score.add(key, False)
        for site in sites:
            score.add('site_conf', False)
            score.add('site_extra', False)
            for _url in URLS[site]:
                score.add('site_files', False)
        errors.append(f'{node}: узел не ответил на проверку')
        return

    s = sections(out)
    pkgs = dict(line.split(' ', 1) for line in s.get('PKG', []) if ' ' in line)
    for p in PACKAGES:
        good = pkgs.get(p) == 'OK'
        score.add('pkg', good)
        if not good:
            errors.append(f'{node}: не установлен пакет {p}')

    enabled = next((l for l in s.get('ENABLED', []) if l), '')
    score.add('enabled', enabled == 'enabled')
    if enabled != 'enabled':
        errors.append(f'{node}: nginx не добавлен в автозагрузку ({enabled or "нет службы"})')
    active = next((l for l in s.get('ACTIVE', []) if l), '')
    score.add('active', active == 'active')
    if active != 'active':
        errors.append(f'{node}: nginx не запущен ({active or "нет службы"})')
    test = [l for l in s.get('NGINXT', []) if l]
    score.add('nginx_t', test == ['OK'])
    if test != ['OK']:
        # без даты/PID и итоговой строки «test failed»
        msg = ' '.join(NGINX_LOG_PREFIX.sub('', l) for l in test if 'test failed' not in l)
        errors.append(f'{node}: nginx -t с ошибкой: {msg[:200] or "nginx не найден"}')
    nconf = s.get('NGINXCONF', [])
    score.add('nginx_conf', 'INCLUDE' in nconf)
    if 'INCLUDE' not in nconf:
        errors.append(f'{node}: /etc/nginx/nginx.conf не подключает conf.d/*.conf')
    if 'MODIFIED' in nconf:
        remarks.append(f'{node}: /etc/nginx/nginx.conf изменён относительно пакета')

    for site in sites:
        conf = f'{CONF_DIR}/{site}.conf'
        data = b64_value(s.get('CONF ' + site, []))
        if data is None:
            score.add('site_conf', False)
            errors.append(f'{node}: нет конфига {conf}')
        else:
            bad = site_conf_problems(site, data.decode('utf-8', errors='replace'))
            score.add('site_conf', not bad)
            if bad:
                errors.append(f'{node}: {conf} — неверно: {", ".join(bad)}')

        for url in URLS[site]:
            path = file_path(site, url)
            data = b64_value(s.get('FILE ' + path, []))
            if data is None:
                score.add('site_files', False)
                errors.append(f'{node}: нет файла {path}')
                continue
            problem = content_problem(data, expected_lines(site, url))
            score.add('site_files', problem is None)
            if problem:
                errors.append(f'{node}: {path} — содержимое не по эталону ({problem})')

        tree = s.get('TREE ' + site, [])
        root = SITES[site][1]
        if not tree or tree[0] != 'ROOTOK':
            score.add('site_extra', False)
            errors.append(f'{node}: нет каталога {root}')
            continue
        extra = sorted(p for p in tree[1:] if p and p not in expected_tree(site))
        score.add('site_extra', not extra)
        if extra:
            shown = ', '.join(extra[:5]) + (f' и ещё {len(extra) - 5}' if len(extra) > 5 else '')
            errors.append(f'{node}: в {root} лишнее: {shown}')


def parse_hosts(data):
    entries = []
    for line in data.decode('utf-8', errors='replace').split('\n'):
        line = line.split('#', 1)[0].strip()
        tok = line.split()
        if len(tok) >= 2:
            entries += [(tok[0], name.lower()) for name in tok[1:]]
    return entries


def check_r(out, score, errors):
    urls = all_urls()
    names = [(node, name) for node in APP_IPS for name in node_names(node)]
    if not responded(out):
        for _ in names:
            score.add('resolve', False)
        score.add('hosts_ok', False)
        for _ in urls:
            score.add('curl', False)
        errors.append(f'{R_NODE}: узел не ответил на проверку')
        return

    s = sections(out)
    hosts = s.get('HOSTS', [])
    entries = parse_hosts(base64.b64decode(hosts[0]) if hosts and hosts[0] else b'')
    resolved = dict((l.split(' ', 1) + [''])[:2] for l in s.get('GETENT', []) if l)
    for node, name in names:
        ip = APP_IPS[node]
        got = resolved.get(name, '').strip()
        in_file = (ip, name) in entries
        score.add('resolve', got == ip and in_file)
        if got != ip:
            errors.append(f'{R_NODE}: {name} разрешается в {got or "ничего"}, а должно в {ip}')
        elif not in_file:
            errors.append(f'{R_NODE}: {name} не записан в /etc/hosts')

    by_name = {}
    for ip, name in entries:
        family = 'v6' if ':' in ip else 'v4'
        by_name.setdefault((name, family), set()).add(ip)
    problems = [f'{name} → {", ".join(sorted(ips))}'
                for (name, _f), ips in sorted(by_name.items()) if len(ips) > 1]
    if ('127.0.0.1', 'localhost') not in entries:
        problems.append('нет записи 127.0.0.1 localhost')
    bad_lo = sorted({ip for ip, name in entries if name == 'localhost'
                     and not (ip.startswith('127.') or ip == '::1')})
    if bad_lo:
        problems.append(f'localhost указывает на {", ".join(bad_lo)}')
    score.add('hosts_ok', not problems)
    if problems:
        errors.append(f'{R_NODE}: /etc/hosts: {"; ".join(problems)}')

    results = {}
    for line in s.get('CURL', []):
        parts = line.split(' ')
        if parts and parts[0].isdigit():
            results[int(parts[0])] = parts[1:]
    for i, (site, url, full) in enumerate(urls):
        res = results.get(i, [])
        code = res[0] if res else ''
        try:
            body = base64.b64decode(res[1]) if len(res) > 1 else b''
        except ValueError:
            body = None
        if code != '200':
            score.add('curl', False)
            what = 'нет ответа' if code in ('', '000') else f'код {code}'
            errors.append(f'{R_NODE}: {full} — {what}')
            continue
        problem = None if body is not None and content_problem(body, expected_lines(site, url)) is None \
            else 'тело ответа не совпадает с эталоном'
        score.add('curl', problem is None)
        if problem:
            errors.append(f'{R_NODE}: {full} — {problem}')


def key_package_missing(node, out):
    """None, если KEY_PACKAGE на узле установлен, иначе причина."""
    if not responded(out):
        return f'{node} (узел не ответил)'
    pkgs = dict(line.split(' ', 1) for line in sections(out).get('PKG', []) if ' ' in line)
    return None if pkgs.get(KEY_PACKAGE) == 'OK' else node


async def check(ctx):
    nodes = list(APP_IPS)
    outs = await asyncio.gather(ctx.run(R_NODE, r_script()),
                                *(ctx.run(node, app_script(node)) for node in nodes))
    score, errors, remarks = Score(), [], []
    if KEY_PACKAGE:
        missing = [m for m in (key_package_missing(n, o) for n, o in zip(nodes, outs[1:])) if m]
        if missing:
            # Ключевое требование не выполнено: пункты с полным max, но 0 баллов
            check_r(outs[0], score, [])
            for node, out in zip(nodes, outs[1:]):
                check_app(node, out, score, [], [])
            ctx.error(f'{KEY_PACKAGE} не установлен: {", ".join(missing)}. Ключевое требование '
                      'лабы не выполнено — результат обнулён, остальное не засчитывается')
            for key in POINTS:
                ctx.add_check(LABELS[key], 0, score.max[key])
            return
    check_r(outs[0], score, errors)
    for node, out in zip(nodes, outs[1:]):
        check_app(node, out, score, errors, remarks)
    for e in errors:
        ctx.error(e)
    for r in remarks:
        ctx.error(f'Замечание: {r}')
    for key in POINTS:
        ctx.add_check(LABELS[key], score.got[key], score.max[key])
