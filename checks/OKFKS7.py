"""Доп. проверки лабы OKFKS7 (самостоятельная): виртуальные хосты nginx.

Студент сам выбирал, где лежат файлы сайтов, поэтому заранее известны только
URL, узлы и индексные файлы. Пути видны из ответов curl и проверяются на
узлах. Проверка только читает: на узлах ничего не меняется.

Ответ на каждый URL — ровно две строки: абсолютный путь к файлу на узле и
путь из URL (пробелы в конце строк и финальный перевод строки не важны).

Фаза 1, узел R (Router):
  - имена сайтов разрешаются в адрес узла из эталона и записаны в /etc/hosts
    (форма записи не важна); дубли с разными адресами и испорченный
    localhost — замечание;
  - каждый URL запрашивается по имени (через /etc/hosts, без --resolve и без
    прокси): код 200, две строки, вторая — путь из URL, первая — абсолютный
    путь, заканчивающийся путём из URL (для URL на «/» — путём и индексным
    файлом сайта).
Фаза 2, узлы app1..app4 (пути — из ответов фазы 1):
  - nginx установлен, enabled, active, `nginx -t` проходит;
  - по пути из первой строки есть обычный файл, содержимое — как тело ответа;
  - root сайта (первая строка минус вторая и индексный файл) одинаков у всех
    URL сайта и совпадает с root в его блоке server (`nginx -T`); root двух
    сайтов узла разные и не вложены друг в друга;
  - каждый сайт — в отдельном /etc/nginx/conf.d/*.conf: server_name, порт 80,
    index из эталона (для index.html можно не указывать);
  - изменённый /etc/nginx/nginx.conf — замечание.
Для неудачного запроса причина уточняется по error.log узла.

Оценка только по этим пунктам и Hostnames (ONLY_EXTRA).
Задание то же, что в OKFKS_5 (checks/OKFKS_5.py).
На сервере лежит в /pnet/checks/OKFKS7.py.
"""

import asyncio
import base64
import datetime
import posixpath
import re
import shlex

ONLY_EXTRA = True

# ------------------------------------------------------------------ эталон
R_NODES = ['R', 'Router']      # первый из имеющихся в лабе
APP_IPS = {'app1': '10.0.1.1', 'app2': '10.0.1.2', 'app3': '10.0.1.3', 'app4': '10.0.1.4'}
CONF_DIR = '/etc/nginx/conf.d'
NGINX_CONF = '/etc/nginx/nginx.conf'
ERROR_LOG = '/var/log/nginx/error.log'
DEFAULT_INDEX = 'index.html'   # index, который nginx использует без директивы
LOG_FRESH = 300                # строки error.log старше (сек) — не от этой проверки

# сайт: (узел, индексный файл)
SITES = {
    'shop.lab':  ('app1', 'index.html'),
    'blog.lab':  ('app1', 'home.html'),
    'wiki.lab':  ('app2', 'start.html'),
    'mail.lab':  ('app2', 'main.html'),
    'docs.lab':  ('app3', 'readme.html'),
    'photo.lab': ('app3', 'gallery.html'),
    'news.lab':  ('app4', 'front.html'),
    'game.lab':  ('app4', 'menu.html'),
}

URLS = {
    'shop.lab':  ['/', '/catalog/', '/catalog/cups/red.html'],
    'blog.lab':  ['/', '/2026/october.html', '/authors/ivan.txt'],
    'wiki.lab':  ['/', '/linux/', '/linux/commands/ls.html'],
    'mail.lab':  ['/', '/inbox/new.html'],
    'docs.lab':  ['/', '/guide.html', '/api/v1/users.html'],
    'photo.lab': ['/', '/albums/', '/albums/sea/info.txt'],
    'news.lab':  ['/', '/sport/', '/sport/football.html'],
    'game.lab':  ['/', '/levels/1/start.html', '/rules.txt'],
}

# Баллы за единицу пункта (имя, узел, URL, сайт)
POINTS = {
    'resolve': 1,      # за имя сайта на R
    'pkg': 1,          # за узел
    'enabled': 1,
    'active': 1,
    'nginx_t': 1,
    'curl': 1,         # за URL: код, две строки, вид строк
    'file': 1,         # за URL: файл на узле совпадает с ответом
    'root': 1,         # за сайт: root одинаков у URL и совпадает с конфигом
    'roots_apart': 1,  # за узел: root сайтов разные и не вложены
    'site_conf': 1,    # за сайт: отдельный conf.d/*.conf, server_name, 80, index
}

LABELS = {
    'resolve': 'R: имена сайтов в /etc/hosts',
    'pkg': 'Пакет nginx',
    'enabled': 'nginx в автозагрузке',
    'active': 'nginx запущен',
    'nginx_t': 'Конфигурация nginx валидна (nginx -t)',
    'curl': 'Ответы сайтов с R',
    'file': 'Файлы сайтов на узлах',
    'root': 'root сайтов',
    'roots_apart': 'root сайтов узла не пересекаются',
    'site_conf': 'Конфиги сайтов в conf.d',
}

CURL_ERRORS = {
    '6': 'имя не разрешается',
    '7': 'соединение отклонено — nginx не слушает порт 80',
    '28': 'нет ответа за отведённое время',
    '52': 'сервер закрыл соединение без ответа',
}


# ------------------------------------------------------------------ общее
def all_urls():
    return [(site, url, f'http://{site}{url}') for site in SITES for url in URLS[site]]


def suffix(site, url):
    """Чем должна заканчиваться первая строка ответа."""
    return url + SITES[site][1] if url.endswith('/') else url


def norm_lines(data):
    """Содержимое файла/ответа -> строки без хвостовых пробелов и без одного
    финального перевода строки."""
    text = data.decode('utf-8', errors='replace')
    if text.endswith('\n'):
        text = text[:-1]
    return [line.rstrip(' \t\r') for line in text.split('\n')]


def norm_root(path):
    return re.sub('/+', '/', path).rstrip('/') or '/'


def nested(a, b):
    """a и b совпадают или одно внутри другого (по компонентам пути)."""
    ca = [c for c in a.split('/') if c]
    cb = [c for c in b.split('/') if c]
    n = min(len(ca), len(cb))
    return ca[:n] == cb[:n]


def short(text, n=100):
    return text if len(text) <= n else text[:n] + '…'


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


def first_line(lines):
    return next((l for l in lines if l), '')


def b64(text):
    try:
        return base64.b64decode(text)
    except ValueError:
        return None


def responded(out):
    return bool(out) and not out.startswith('NONE') and '==END' in out


# ------------------------------------------------------------------ R
def r_script():
    q = shlex.quote
    lines = ['echo ==GETENT']
    for site in SITES:
        lines.append(f"echo {q(site)} $(getent ahostsv4 {q(site)} 2>/dev/null | awk 'NR==1{{print $1}}')")
    lines.append('echo ==HOSTS; base64 -w0 /etc/hosts 2>/dev/null; echo')
    # Запросы параллельно: последовательные таймауты не уложились бы в лимит qga
    lines.append('d=$(mktemp -d)')
    for i, (_site, _url, full) in enumerate(all_urls()):
        lines.append(f"( curl -s --noproxy '*' --connect-timeout 2 -m 4 -o \"$d/{i}\" "
                     f"-w '%{{http_code}}|%{{remote_ip}}' {q(full)} > \"$d/{i}.w\" 2>/dev/null; "
                     f"echo $? > \"$d/{i}.rc\" ) &")
    lines.append('wait')
    lines.append('echo ==CURL')
    for i, _ in enumerate(all_urls()):
        lines.append(f"echo \"{i}|$(cat \"$d/{i}.rc\" 2>/dev/null)|$(cat \"$d/{i}.w\" 2>/dev/null)|"
                     f"$(head -c 65536 \"$d/{i}\" 2>/dev/null | base64 -w0)\"")
    lines.append('rm -rf "$d"; echo ==END')
    return '\n'.join(lines)


def parse_hosts(data):
    entries = []
    for line in data.decode('utf-8', errors='replace').split('\n'):
        tok = line.split('#', 1)[0].split()
        if len(tok) >= 2:
            entries += [(tok[0], name.lower()) for name in tok[1:]]
    return entries


def hosts_remarks(entries):
    by_name = {}
    for ip, name in entries:
        by_name.setdefault((name, 'v6' if ':' in ip else 'v4'), set()).add(ip)
    problems = [f'{name} → {", ".join(sorted(ips))}'
                for (name, _f), ips in sorted(by_name.items()) if len(ips) > 1]
    if ('127.0.0.1', 'localhost') not in entries:
        problems.append('нет записи 127.0.0.1 localhost')
    bad_lo = sorted({ip for ip, name in entries if name == 'localhost'
                     and not (ip.startswith('127.') or ip == '::1')})
    if bad_lo:
        problems.append(f'localhost указывает на {", ".join(bad_lo)}')
    return problems


def eval_response(site, url, rc, code, body, resolved):
    """Пункты 3.1–3.3 -> (проблема | None, root | None, путь для 3.4 | None)."""
    node = SITES[site][0]
    if code != '200':
        if code and code != '000':
            what = f'код ответа {code}'
        else:
            what = CURL_ERRORS.get(rc, f'нет ответа (ошибка curl {rc or "?"})')
        if resolved and resolved != APP_IPS[node]:
            what += f' (имя разрешается в {resolved}, а сайт на {node})'
        return what, None, None
    lines = norm_lines(body)
    path = lines[0] if lines[0].startswith('/') else None
    if b'Welcome to nginx' in body:
        return 'стандартная страница nginx вместо сайта (ответил server по умолчанию)', None, None
    if len(lines) != 2:
        return f'в ответе {len(lines)} строк(и), а должно быть 2', None, path
    first, second = lines
    if second != url:
        return f'вторая строка «{short(second)}», а должна быть «{url}»', None, path
    if not path:
        return f'первая строка «{short(first)}» — не абсолютный путь', None, None
    end = suffix(site, url)
    if not first.endswith(end):
        return f'первая строка «{short(first)}» должна заканчиваться на «{end}»', None, path
    return None, norm_root(first[:-len(end)]), path


def check_r(r_node, out):
    """-> (результаты URL, {сайт: адрес}, [ошибки], [замечания], баллы resolve)."""
    urls = all_urls()
    if not responded(out):
        # problem '' — URL не засчитан, отдельного сообщения нет
        res = [dict(site=s, url=u, full=f, code='', problem='', root=None, path=None, body=None)
               for s, u, f in urls]
        return res, {}, [f'{r_node}: узел не ответил на проверку'], [], {}

    s = sections(out)
    errors, remarks = [], []
    hosts = first_line(s.get('HOSTS', []))
    entries = parse_hosts(b64(hosts) or b'')
    resolved = {}
    for line in s.get('GETENT', []):
        if line:
            name, _, ip = line.partition(' ')
            resolved[name] = ip.strip()
    resolve_ok = {}
    for site, (node, _index) in SITES.items():
        ip, got = APP_IPS[node], resolved.get(site, '')
        resolve_ok[site] = got == ip and (ip, site) in entries
        if got != ip:
            errors.append(f'{r_node}: {site} разрешается в {got or "ничего"}, а должно в {ip} ({node})')
        elif (ip, site) not in entries:
            errors.append(f'{r_node}: {site} не записан в /etc/hosts')
    problems = hosts_remarks(entries)
    if problems:
        remarks.append(f'{r_node}: /etc/hosts: {"; ".join(problems)}')

    raw = {}
    for line in s.get('CURL', []):
        parts = line.split('|')
        if parts[0].isdigit():
            raw[int(parts[0])] = (parts[1:] + ['', '', '', ''])[:4]
    res = []
    for i, (site, url, full) in enumerate(urls):
        rc, code, _ip, body64 = raw.get(i, ('', '', '', ''))
        body = b64(body64)
        if body is None:
            code = ''
        problem, root, path = eval_response(site, url, rc.strip(), code.strip(), body or b'',
                                            resolved.get(site, ''))
        res.append(dict(site=site, url=url, full=full, code=code.strip(), problem=problem,
                        root=root, path=path, body=body))
    return res, resolved, errors, remarks, resolve_ok


# ------------------------------------------------------------------ app
def app_script(node, url_res):
    q = shlex.quote
    lines = [
        "echo ==PKG; if rpm -q nginx >/dev/null 2>&1 || dpkg -s nginx 2>/dev/null | "
        "grep -q '^Status: install ok installed'; then echo OK; else echo NO; fi",
        'echo ==ENABLED; systemctl is-enabled nginx 2>/dev/null',
        'echo ==ACTIVE; systemctl is-active nginx 2>/dev/null',
        'echo ==NGINXT; if nginx -t >/dev/null 2>&1; then echo OK; else nginx -t 2>&1 | tail -n 3; fi',
        # nginx.conf изменён относительно пакета: rpm -V или md5 conffile в dpkg
        'echo ==MAINCONF',
        f"rpm -V nginx 2>/dev/null | grep -q ' {NGINX_CONF}$' && echo MODIFIED",
        "s=$(dpkg-query -W -f='${Conffiles}\\n' nginx-common nginx 2>/dev/null | "
        f"awk '$1==\"{NGINX_CONF}\"{{print $2; exit}}'); "
        f"[ -n \"$s\" ] && [ \"$s\" != \"$(md5sum < {NGINX_CONF} | cut -d' ' -f1)\" ] && echo MODIFIED",
        # итоговая конфигурация; если nginx -T не работает — сами файлы
        'echo ==CONF; t=$(nginx -T 2>/dev/null | base64 -w0)',
        'if [ -n "$t" ]; then echo T; echo "$t"; else echo RAW; '
        f'for f in {NGINX_CONF} {CONF_DIR}/*.conf; do [ -f "$f" ] && '
        'printf \'%s\\t%s\\n\' "$f" "$(base64 -w0 < "$f")"; done; fi',
        "echo ==NOW; date '+%Y/%m/%d %H:%M:%S'",
    ]
    for i, r in url_res:
        if r['path']:
            p = q(r['path'])
            lines.append(f"echo ==FILE {i}; if [ -f {p} ]; then printf 'B64:'; head -c 65536 {p} | "
                         f"base64 -w0; echo; elif [ -e {p} ]; then echo NOTREG; else echo MISSING; fi")
        if r['code'] not in ('', '000', '200'):
            req = q(f'request: "GET {r["url"]} HTTP')
            host = q(f'host: "{r["site"]}"')
            lines.append(f"echo ==LOG {i}; grep -F -- {req} {ERROR_LOG} 2>/dev/null | "
                         f"grep -F -- {host} | tail -n 1 | cut -c1-800")
    lines.append('echo ==END')
    return '\n'.join(lines)


NGINX_LOG_PREFIX = re.compile(r'^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[\w+\] \d+#\d+: (?:\*\d+ )?')


def log_hint(line, now, site):
    """Строка error.log -> пояснение для студента или None."""
    m = NGINX_LOG_PREFIX.match(line)
    if not m:
        return None
    try:
        t = datetime.datetime.strptime(m.group(1), '%Y/%m/%d %H:%M:%S')
        if now is None or abs((now - t).total_seconds()) > LOG_FRESH:
            return None
    except ValueError:
        return None
    msg = line[m.end():].split(', client: ', 1)[0]
    hint = f'error.log: {short(msg, 200)}'
    srv = re.search(r', server: ([^,]*), request: ', line)
    if srv and srv.group(1) != site:
        hint += f'; запрос обработал server «{srv.group(1) or "без имени"}», а не {site}'
    if 'directory index of' in msg:
        hint += f'; в каталоге нет индексного файла {SITES[site][1]} или он не указан в index'
    if 'Permission denied' in msg and '/home/' in msg:
        hint += ('; у nginx нет доступа к файлам в /home — проверьте права на домашний '
                 'каталог (нужно право x для остальных)')
    return hint


# ------------------------------------------------------------------ nginx-конфиг
TOKEN_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};"\']+')
CONF_HEADER = re.compile(r'^# configuration file (.+):$', re.M)


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


def conf_files(lines):
    """Секция CONF -> {путь: текст}."""
    if not lines:
        return {}
    files = {}
    if lines[0] == 'T':
        text = (b64(lines[1] if len(lines) > 1 else '') or b'').decode('utf-8', errors='replace')
        parts = CONF_HEADER.split(text)
        for i in range(1, len(parts) - 1, 2):
            files[posixpath.normpath(parts[i])] = parts[i + 1]
    else:
        for line in lines[1:]:
            path, _, data = line.partition('\t')
            if path:
                files[posixpath.normpath(path)] = (b64(data) or b'').decode('utf-8', errors='replace')
    return files


def find_servers(items, path, acc):
    for name, _args, sub in items:
        if sub is None:
            continue
        if name == 'server':
            acc.append((path, sub))
        else:
            find_servers(sub, path, acc)


def server_names(srv):
    return [x.lower() for args in directives(srv, 'server_name') for x in args]


def listen_ports(srv):
    ports = []
    for args in directives(srv, 'listen'):
        if not args:
            continue
        a = args[0]
        ports.append(a if a.isdigit() else a.rsplit(':', 1)[1] if ':' in a else '80')
    return ports or ['80']    # без listen nginx слушает 80


def location_root(srv):
    return next((sub for n, a, sub in srv if n == 'location' and sub is not None and a == ['/']), None)


def check_site_conf(node, site, servers):
    """-> (root из конфига | None, [ошибки])."""
    index = SITES[site][1]
    blocks = [(p, b) for p, b in servers if site in server_names(b)]
    if not blocks:
        return None, [f'{node}: нет блока server с server_name {site}']
    blocks80 = [(p, b) for p, b in blocks if '80' in listen_ports(b)]
    if not blocks80:
        return None, [f'{node}: server {site} не слушает порт 80']
    if len(blocks80) > 1:
        files = ', '.join(sorted({p for p, _b in blocks80}))
        return None, [f'{node}: {site} описан в нескольких блоках server ({files})']
    path, srv = blocks80[0]
    bad = []
    if not re.fullmatch(re.escape(CONF_DIR) + r'/[^/]+\.conf', path):
        bad.append(f'описан в {path}, а должен в отдельном файле {CONF_DIR}/*.conf')
    else:
        others = sorted({s for p, b in servers if p == path for s in SITES
                         if s != site and s in server_names(b)})
        if others:
            bad.append(f'описан в {path} вместе с {", ".join(others)} — нужен отдельный файл')
    loc = location_root(srv)
    indexes = directives(srv, 'index') or (loc is not None and directives(loc, 'index'))
    if index not in ([x for args in indexes for x in args] if indexes else [DEFAULT_INDEX]):
        bad.append(f'в index нет {index}')
    roots = directives(srv, 'root') or (loc is not None and directives(loc, 'root'))
    root = norm_root(roots[-1][0]) if roots and roots[-1] else None
    if root is None:
        bad.append('в блоке server нет root')
    return root, [f'{node}: {site} — {b}' for b in bad]


# ------------------------------------------------------------------ проверки
class Score:
    def __init__(self):
        self.got = dict.fromkeys(POINTS, 0)
        self.max = dict.fromkeys(POINTS, 0)

    def add(self, key, good):
        self.max[key] += POINTS[key]
        if good:
            self.got[key] += POINTS[key]


def check_app(node, out, url_res, score, errors, remarks):
    """Пункты узла и 3.4 его URL. -> {сайт: root из конфига} или None."""
    if not responded(out):
        for key in ('pkg', 'enabled', 'active', 'nginx_t'):
            score.add(key, False)
        for _i, r in url_res:
            score.add('file', False)
        for _site in (s for s, (n, _x) in SITES.items() if n == node):
            score.add('site_conf', False)
        errors.append(f'{node}: узел не ответил на проверку')
        return None

    s = sections(out)
    pkg = first_line(s.get('PKG', [])) == 'OK'
    score.add('pkg', pkg)
    if not pkg:
        errors.append(f'{node}: не установлен пакет nginx')
    enabled = first_line(s.get('ENABLED', []))
    score.add('enabled', enabled == 'enabled')
    if enabled != 'enabled':
        errors.append(f'{node}: nginx не добавлен в автозагрузку ({enabled or "нет службы"})')
    active = first_line(s.get('ACTIVE', []))
    score.add('active', active == 'active')
    if active != 'active':
        errors.append(f'{node}: nginx не запущен ({active or "нет службы"})')
    test = [l for l in s.get('NGINXT', []) if l]
    score.add('nginx_t', test == ['OK'])
    if test != ['OK']:
        msg = ' '.join(re.sub(r'^(?:\S+ \S+ |nginx: )\[\w+\] (?:\d+#\d+: )?', '', l)
                       for l in test if 'test failed' not in l)
        errors.append(f'{node}: nginx -t с ошибкой: {short(msg, 200) or "nginx не найден"}')
    if 'MODIFIED' in s.get('MAINCONF', []):
        remarks.append(f'{node}: {NGINX_CONF} изменён относительно пакета')

    try:
        now = datetime.datetime.strptime(first_line(s.get('NOW', [])), '%Y/%m/%d %H:%M:%S')
    except ValueError:
        now = None
    for i, r in url_res:
        hint = log_hint(first_line(s.get(f'LOG {i}', [])), now, r['site'])
        if hint and r['problem']:
            r['problem'] += f' — {hint}'
        if not r['path']:
            score.add('file', False)
            continue
        state = first_line(s.get(f'FILE {i}', []))
        if state.startswith('B64:'):
            data = b64(state[4:])
            good = data is not None and r['body'] is not None and norm_lines(data) == norm_lines(r['body'])
            score.add('file', good)
            if not good:
                errors.append(f'{node}: {r["path"]} не совпадает с ответом на {r["full"]}')
        else:
            score.add('file', False)
            what = 'не обычный файл' if state == 'NOTREG' else 'нет такого файла'
            errors.append(f'{node}: {r["path"]} (из ответа на {r["full"]}) — {what}')

    servers = []
    for path, text in conf_files(s.get('CONF', [])).items():
        find_servers(parse_nginx(text), path, servers)
    conf_roots = {}
    for site in (x for x, (n, _i) in SITES.items() if n == node):
        root, bad = check_site_conf(node, site, servers)
        conf_roots[site] = root
        score.add('site_conf', not bad)
        errors.extend(bad)
    return conf_roots


def check_roots(node, results, conf_roots, score, errors):
    """Раздел 4 для сайтов узла."""
    site_roots = {}
    for site in (x for x, (n, _i) in SITES.items() if n == node):
        got = {r['url']: r['root'] for r in results if r['site'] == site and r['root']}
        roots = set(got.values())
        conf = conf_roots.get(site) if conf_roots else None
        site_roots[site] = roots.pop() if len(roots) == 1 else conf
        if not got:
            score.add('root', False)
            if any(r['problem'] for r in results if r['site'] == site):   # R ответил
                errors.append(f'{node}: root {site} не определить — нет ни одного корректного ответа')
        elif len(set(got.values())) > 1:
            score.add('root', False)
            shown = ', '.join(f'{u} → {r}' for u, r in got.items())
            errors.append(f'{node}: у URL {site} разный root: {shown}')
        elif conf is None:
            score.add('root', False)
            if conf_roots is not None:
                errors.append(f'{node}: root {site} ({site_roots[site]}) не с чем сравнить — '
                              'root сайта в конфигурации не найден')
        elif conf != site_roots[site]:
            score.add('root', False)
            errors.append(f'{node}: root {site} по ответам {site_roots[site]}, а в конфигурации {conf}')
        else:
            score.add('root', True)

    (s1, r1), (s2, r2) = list(site_roots.items())[:2]
    if r1 is None or r2 is None:
        score.add('roots_apart', False)
        errors.append(f'{node}: не удалось определить root {s1} и {s2} для сравнения')
    elif r1 == r2:
        score.add('roots_apart', False)
        errors.append(f'{node}: у {s1} и {s2} один и тот же root {r1}')
    elif nested(r1, r2):
        outer, inner = ((s1, r1), (s2, r2)) if len(r1) < len(r2) else ((s2, r2), (s1, r1))
        score.add('roots_apart', False)
        errors.append(f'{node}: root {inner[0]} ({inner[1]}) внутри root {outer[0]} ({outer[1]})')
    else:
        score.add('roots_apart', True)


async def check(ctx):
    r_node = next((n for n in R_NODES if n in ctx.nodes), R_NODES[0])
    results, _resolved, errors, remarks, resolve_ok = check_r(r_node, await ctx.run(r_node, r_script()))
    score = Score()
    for site in SITES:
        score.add('resolve', resolve_ok.get(site, False))

    nodes = list(APP_IPS)
    per_node = {node: [(i, r) for i, r in enumerate(results) if SITES[r['site']][0] == node]
                for node in nodes}
    outs = await asyncio.gather(*(ctx.run(node, app_script(node, per_node[node])) for node in nodes))

    app_errors, conf_roots = [], {}
    for node, out in zip(nodes, outs):
        conf_roots[node] = check_app(node, out, per_node[node], score, app_errors, remarks)

    # ошибки URL — после подсказок из error.log (их добавляет check_app)
    for r in results:
        score.add('curl', r['problem'] is None)
        if r['problem']:
            errors.append(f'{r_node}: {r["full"]} — {r["problem"]}')
    errors += app_errors
    for node in nodes:
        check_roots(node, results, conf_roots[node], score, errors)

    for e in errors:
        ctx.error(e)
    for r in remarks:
        ctx.error(f'Замечание: {r}')
    for key in POINTS:
        ctx.add_check(LABELS[key], score.got[key], score.max[key])
