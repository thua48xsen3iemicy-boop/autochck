"""Подготовка лаб (преднастрой) и индивидуальные варианты студентов.

Лаба с маркером prepare:on в <description> сначала готовится: студент
запускает все узлы и нажимает «Подготовить лабу», а функция prepare(ctx) из
файла лабы (/pnet/checks/<лаба>.py, тот же файл, что и для check(ctx))
раскатывает на узлы начальную настройку. Подготавливаются Linux-узлы
(через qemu-guest-agent) и Cisco IOL/vIOS (конфиг через консоль).

Вариант студента описывается в файле лабы:

    VARIANT = {
        'lan':  net('10.0.0.0/8', 24),           # своя сеть /24 из 10.0.0.0/8
        'dmz':  net('172.16.0.0/12', 28),
        'srv':  host_in('lan'),                   # случайный адрес в lan
        'vlan': choice(10, 20, 30),
        'user': text('user###'),                  # user + 3 цифры
    }

    def variant(v):                               # необязательно: производные
        v['gw'] = v['lan'].host(1)

Значения выбираются не случайно, а из хеша «соль + лаба + логин»: у одного
студента вариант всегда один и тот же (в том числе после вайпа и повторной
подготовки), у разных студентов — разные. Сети из net()/nets() не
пересекаются друг с другом. SALT = '...' в файле лабы перемешивает варианты
заново (после смены соли лабы нужно подготовить заново).

Предпросмотр вариантов для преподавателя:

    python3 labprep.py /pnet/checks/<лаба>.py ivanov petrov sidorov

Модуль не зависит от сервиса автопроверки и при деплое лежит рядом с
myapi_with_reload.py (как check_labels.py).
"""

import base64
import hashlib
import ipaddress
import json
import random
import re
import shlex
import string


# ================================================================== варианты

class Addr:
    """Адрес узла в сети: str() — '10.1.2.10', .cidr — '10.1.2.10/24'."""

    def __init__(self, iface):
        self._i = ipaddress.ip_interface(iface)

    ip = property(lambda self: str(self._i.ip))
    prefix = property(lambda self: self._i.network.prefixlen)
    mask = property(lambda self: str(self._i.netmask))
    cidr = property(lambda self: f'{self._i.ip}/{self._i.network.prefixlen}')
    net = property(lambda self: Net(self._i.network))

    def __str__(self):
        return self.ip

    __format__ = lambda self, spec: format(str(self), spec)
    __repr__ = lambda self: f'Addr({self.cidr!r})'
    __eq__ = lambda self, o: isinstance(o, Addr) and self._i == o._i
    __hash__ = lambda self: hash(self._i)


class Net:
    """Сеть: str() — '10.1.2.0/24'.

    .host(1) — первый адрес (обычно шлюз), .host(-1) — последний, .gw — то же,
    что host(1); .address, .prefix, .mask, .broadcast; .size — число адресов
    узлов; .split(26) — список подсетей /26.
    """

    def __init__(self, network):
        self._n = ipaddress.ip_network(network, strict=False)

    address = property(lambda self: str(self._n.network_address))
    prefix = property(lambda self: self._n.prefixlen)
    mask = property(lambda self: str(self._n.netmask))
    broadcast = property(lambda self: str(self._n.broadcast_address))
    size = property(lambda self: max(self._n.num_addresses - 2, 0))
    gw = property(lambda self: self.host(1))

    def host(self, n):
        """n-й адрес узла сети (с 1); отрицательный — с конца (-1 — последний)."""
        if n == 0 or abs(n) > self.size:
            raise ValueError(f'в сети {self} нет адреса узла №{n} (всего {self.size})')
        base = self._n.network_address + n if n > 0 else self._n.broadcast_address + n
        return Addr(f'{base}/{self.prefix}')

    def split(self, prefix):
        return [Net(s) for s in self._n.subnets(new_prefix=prefix)]

    def __contains__(self, addr):
        ip = addr._i.ip if isinstance(addr, Addr) else ipaddress.ip_address(str(addr).split('/')[0])
        return ip in self._n

    def __str__(self):
        return str(self._n)

    __format__ = lambda self, spec: format(str(self), spec)
    __repr__ = lambda self: f'Net({str(self)!r})'
    __eq__ = lambda self, o: isinstance(o, Net) and self._n == o._n
    __hash__ = lambda self: hash(self._n)


class Variant(dict):
    """Значения варианта: v['lan'] или v.lan. v.random — генератор случайных
    чисел этого студента (для своих правил в variant(v))."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class _Gen:
    def __init__(self, rng):
        self.rng = rng
        self.used_nets = []        # сети net()/nets(): не должны пересекаться
        self.used_hosts = {}       # Net -> выданные host_in() адреса

    def take_net(self, pool, prefix, exclude):
        pool = ipaddress.ip_network(pool, strict=False)
        if prefix < pool.prefixlen:
            raise ValueError(f'префикс /{prefix} больше пула {pool}')
        excl = [ipaddress.ip_network(e, strict=False) for e in exclude]
        count = 2 ** (prefix - pool.prefixlen)
        step = 2 ** (pool.max_prefixlen - prefix)
        base = int(pool.network_address)
        for _ in range(2000):
            cand = ipaddress.ip_network((base + self.rng.randrange(count) * step, prefix))
            if not any(cand.overlaps(u) for u in self.used_nets + excl):
                self.used_nets.append(cand)
                return Net(cand)
        raise ValueError(f'не удалось подобрать непересекающуюся сеть /{prefix} в {pool}')


class _Builder:
    def make(self, g, v):
        raise NotImplementedError


class net(_Builder):
    """Случайная сеть с префиксом prefix внутри пула pool. Не пересекается с
    другими сетями варианта и с сетями из exclude."""

    def __init__(self, pool='10.0.0.0/8', prefix=24, exclude=()):
        self.pool, self.prefix, self.exclude = pool, prefix, list(exclude)

    def make(self, g, v):
        return g.take_net(self.pool, self.prefix, self.exclude)


class nets(_Builder):
    """Список из count непересекающихся сетей (см. net)."""

    def __init__(self, count, pool='10.0.0.0/8', prefix=24, exclude=()):
        self.count, self.one = count, net(pool, prefix, exclude)

    def make(self, g, v):
        return [self.one.make(g, v) for _ in range(self.count)]


class subnets(_Builder):
    """Подсети сети v[name] с префиксом prefix: все по порядку или count
    случайных (в порядке возрастания)."""

    def __init__(self, name, prefix, count=None):
        self.name, self.prefix, self.count = name, prefix, count

    def make(self, g, v):
        parts = _ref(v, self.name, Net).split(self.prefix)
        if self.count is None:
            return parts
        idx = sorted(g.rng.sample(range(len(parts)), self.count))
        return [parts[i] for i in idx]


class host_in(_Builder):
    """Случайный адрес узла в сети v[name]. Первые reserve адресов сети
    (host(1)..host(reserve)) не выдаются — их можно занимать вручную, например
    шлюз host(1). Разные host_in одной сети не совпадают."""

    def __init__(self, name, reserve=10):
        self.name, self.reserve = name, reserve

    def make(self, g, v):
        n = _ref(v, self.name, Net)
        reserve = min(self.reserve, max(n.size - 1, 0))
        used = g.used_hosts.setdefault(n, set())
        free = [i for i in range(reserve + 1, n.size + 1) if i not in used]
        if not free:
            raise ValueError(f'в сети {n} кончились свободные адреса')
        i = g.rng.choice(free)
        used.add(i)
        return n.host(i)


class choice(_Builder):
    """Одно значение из перечисленных: choice(10, 20, 30)."""

    def __init__(self, *items):
        if len(items) == 1 and isinstance(items[0], (list, tuple)):
            items = tuple(items[0])
        self.items = items

    def make(self, g, v):
        return g.rng.choice(self.items)


class number(_Builder):
    """Целое число от lo до hi включительно."""

    def __init__(self, lo, hi):
        self.lo, self.hi = lo, hi

    def make(self, g, v):
        return g.rng.randint(self.lo, self.hi)


class text(_Builder):
    """Строка по шаблону: '#' — цифра, '?' — строчная латинская буква,
    остальное как есть. text('user###') -> 'user482'."""

    def __init__(self, pattern):
        self.pattern = pattern

    def make(self, g, v):
        out = []
        for ch in self.pattern:
            if ch == '#':
                out.append(g.rng.choice(string.digits))
            elif ch == '?':
                out.append(g.rng.choice(string.ascii_lowercase))
            else:
                out.append(ch)
        return ''.join(out)


def _ref(v, name, kind):
    if name not in v:
        raise ValueError(f'значение {name!r} должно быть описано в VARIANT раньше')
    val = v[name]
    if not isinstance(val, kind):
        raise ValueError(f'{name!r} — не {kind.__name__}')
    return val


def has_variant(module):
    return bool(getattr(module, 'VARIANT', None)) or callable(getattr(module, 'variant', None))


def make_variant(module, username, lab_stem):
    """Вариант студента для лабы: VARIANT по порядку, затем variant(v)."""
    salt = str(getattr(module, 'SALT', ''))
    key = f'{salt}|{lab_stem}|{username.strip().lower()}'.encode('utf-8')
    rng = random.Random(int.from_bytes(hashlib.sha256(key).digest()[:8], 'big'))
    g = _Gen(rng)
    v = Variant()
    for name, spec in (getattr(module, 'VARIANT', None) or {}).items():
        v[name] = spec.make(g, v) if isinstance(spec, _Builder) else spec
    v.__dict__['random'] = rng
    func = getattr(module, 'variant', None)
    if callable(func):
        func(v)
    return v


def _show(val):
    if isinstance(val, (list, tuple)):
        return ', '.join(_show(x) for x in val)
    if isinstance(val, Addr):
        return val.cidr
    return str(val)


def variant_items(v):
    """[(имя, значение строкой)] для показа студенту; имена с '_' скрыты."""
    return [(k, _show(val)) for k, val in v.items() if not str(k).startswith('_')]


def variant_token(v, lab_stem):
    """Отпечаток варианта: метка подготовки на узлах. Изменился вариант
    (соль, правила) — старая подготовка считается недействительной."""
    raw = json.dumps([lab_stem, variant_items(v)], ensure_ascii=False)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]


def task_text(module, v):
    """TASK из файла лабы с подставленными значениями ('{lan}', '{gw.cidr}')."""
    task = getattr(module, 'TASK', None)
    if not task:
        return None
    try:
        return str(task).format_map(v)
    except (KeyError, AttributeError, IndexError, ValueError) as e:
        return f'{task}\n(ошибка подстановки варианта: {e!r})'


# ================================================================== подготовка

# Тип узла из файла лабы (template) -> семейство ОС для готовых действий
OS_FAMILY = {'linux': 'linux', 'proxmox': 'linux',
             'iol': 'cisco', 'vios': 'cisco', 'viosl2': 'cisco'}

MARKER_PATH = '/etc/autochck-prep'
_IFACE_RE = re.compile(r'^[\w.\-:@]+$')


class ConsoleError(Exception):
    """Консоль узла не ответила или закрылась посреди обмена."""


class PrepareError(Exception):
    """Шаг подготовки не выполнен. teacher=True — ошибка в файле лабы (нет
    узла, неподдерживаемый тип), повтор студентом не поможет."""

    def __init__(self, node, step, detail, teacher=False, hint=None):
        super().__init__(f'{node}: {step}: {detail}')
        self.node, self.step, self.detail, self.teacher = node, step, detail, teacher
        self.hint = hint     # своя подсказка студенту вместо стандартной


def _tail(text, lines=6, limit=600):
    text = (text or '').strip()
    out = '\n'.join(text.splitlines()[-lines:])
    return out[-limit:]


def _write_cmd(path, content, mode=None):
    data = content.encode('utf-8') if isinstance(content, str) else bytes(content)
    b64 = base64.b64encode(data).decode('ascii')
    p = shlex.quote(path)
    cmd = f'mkdir -p "$(dirname {p})" && printf %s {shlex.quote(b64)} | base64 -d > {p}'
    if mode is not None:
        mode = format(mode, 'o') if isinstance(mode, int) else str(mode)
        cmd += f' && chmod {shlex.quote(mode)} {p}'
    return cmd


def linux_set_ip_script(iface, cidr, gw=None, dns=None):
    """Скрипт /bin/sh: адрес на интерфейсе сразу и с сохранением после
    перезагрузки (NetworkManager, netplan или ifupdown — что есть на узле).
    Прежние адреса интерфейса снимаются."""
    q = shlex.quote
    gw = '' if gw is None else str(gw)
    dns_list = [str(d) for d in (dns if isinstance(dns, (list, tuple)) else [dns] if dns else [])]
    yaml = ['network:', '  version: 2', '  ethernets:', f'    {iface}:',
            '      dhcp4: false', f'      addresses: [{cidr}]']
    if gw:
        yaml.append(f'      routes: [{{to: default, via: {gw}}}]')
    if dns_list:
        yaml.append(f'      nameservers: {{addresses: [{", ".join(dns_list)}]}}')
    ifupdown = [f'auto {iface}', f'iface {iface} inet static', f'    address {cidr}']
    if gw:
        ifupdown.append(f'    gateway {gw}')
    if dns_list:
        ifupdown.append(f'    dns-nameservers {" ".join(dns_list)}')
    # Убирает описание интерфейса из файлов ifupdown: строки auto/allow-*
    # с ним и блок iface вместе с его опциями
    awk = ('{ if ($1=="auto" || $1 ~ /^allow-/) { o=$1; n=0; for (i=2;i<=NF;i++) if ($i!=d) { o=o" "$i; n++ }; '
           'if (n>0) print o; skip=0; next } '
           'if ($1=="iface") { skip=($2==d); if (!skip) print; next } '
           'if ($1=="mapping" || $1 ~ /^source/) { skip=0; print; next } '
           'if (!skip) print }')
    return '\n'.join([
        'set -e',
        f'IF={q(iface)}; ADDR={q(cidr)}; GW={q(gw)}; DNS={q(" ".join(dns_list))}',
        'ip link show "$IF" >/dev/null',
        'ip addr flush dev "$IF"',
        'ip addr add "$ADDR" dev "$IF"',
        'ip link set "$IF" up',
        'if [ -n "$GW" ]; then ip route replace default via "$GW" dev "$IF"; fi',
        'if command -v nmcli >/dev/null 2>&1 && nmcli -t -f RUNNING general 2>/dev/null | grep -q running; then',
        '  C=$(nmcli -t -f NAME,DEVICE con show | awk -F: -v d="$IF" \'$2==d {print $1; exit}\')',
        '  if [ -z "$C" ]; then C="autochck-$IF"; nmcli con delete "$C" >/dev/null 2>&1 || true;'
        ' nmcli con add type ethernet ifname "$IF" con-name "$C" >/dev/null; fi',
        '  nmcli con mod "$C" ipv4.method manual ipv4.addresses "$ADDR" ipv4.gateway "$GW" ipv4.dns "$DNS"',
        '  nmcli con up "$C" >/dev/null',
        'elif ls /etc/netplan/*.yaml >/dev/null 2>&1; then',
        f'  {_write_cmd("/etc/netplan/90-autochck-" + iface + ".yaml", chr(10).join(yaml) + chr(10), 0o600)}',
        '  netplan apply',
        'elif [ -f /etc/network/interfaces ]; then',
        '  for f in /etc/network/interfaces /etc/network/interfaces.d/*; do',
        f'    [ -f "$f" ] || continue; awk -v d="$IF" {q(awk)} "$f" > "$f.autochck" && cat "$f.autochck" > "$f" && rm -f "$f.autochck"',
        '  done',
        "  grep -qE '^[[:space:]]*source(-directory)?[[:space:]]+/etc/network/interfaces\\.d' /etc/network/interfaces"
        " || printf '\\nsource /etc/network/interfaces.d/*\\n' >> /etc/network/interfaces",
        f'  {_write_cmd("/etc/network/interfaces.d/autochck-" + iface, chr(10).join(ifupdown) + chr(10))}',
        '  if [ -n "$DNS" ]; then',
        '    if [ -L /etc/resolv.conf ] && command -v resolvectl >/dev/null 2>&1; then resolvectl dns "$IF" $DNS;',
        '    else for d in $DNS; do echo "nameserver $d"; done > /etc/resolv.conf; fi',
        '  fi',
        'fi',
    ])


def cisco_config_lines(text):
    """Строки конфига Cisco для отправки: без пустых, комментариев '!' и
    входа/выхода из режима конфигурации (их добавляет консоль сама)."""
    lines = []
    for raw in str(text).splitlines():
        line = raw.strip()
        if not line or line.startswith('!'):
            continue
        if line.lower() in ('end', 'conf t', 'configure terminal'):
            continue
        lines.append(line)
    return lines


def cisco_verify_lines(lines):
    """Строки, которые IOS хранит в running-config дословно и по которым после
    отправки сверяется результат: hostname и ip address."""
    return [l for l in lines if re.match(r'^(hostname \S+|ip address \d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+)', l)]


def _norm_ws(text):
    return re.sub(r'[ \t]+', ' ', text)


# Метка подготовки на Cisco — alias exec prep<8 hex отпечатка> в конфиге:
# короткое имя из букв и цифр, без якорей в фильтре — меньше зависимости от
# правил конкретного IOS. Старый формат prep-<16 hex> тоже распознаётся
# (чтобы удалить его при повторной подготовке).
CISCO_MARKER_READ = 'show running-config | include alias exec prep'


def cisco_marker_name(token):
    return 'prep' + token[:8]


def cisco_marker_line(token):
    return f'alias exec {cisco_marker_name(token)} show clock'


def cisco_marker_names(output):
    """Имена alias-меток подготовки в выводе running-config."""
    return re.findall(r'alias exec (prep-?[0-9a-f]+)\b', (output or '').lower())


class PrepareContext:
    """То, что доступно функции prepare(ctx) в файле лабы.

    ctx.v                          — вариант студента (VARIANT/variant(v))
    ctx.nodes, ctx.ostype          — узлы лабы и их тип ('linux', 'iol', ...)

    Linux-узлы:
    await ctx.set_ip(узел, интерфейс, адрес, gw=None, dns=None)
                                     адрес — Addr из варианта или '10.1.1.10/24'
    await ctx.set_hostname(узел, имя)
    await ctx.mkdir(узел, путь)
    await ctx.write_file(узел, путь, текст, mode=None)   mode=0o755 и т. п.
    await ctx.shell(узел, 'команда')  — своя команда (sh -c), вывод строкой

    Cisco (IOL, vIOS, vIOS-L2), через консоль:
    await ctx.cisco_config(узел, 'текст конфига', reload=False, expect=())
        строки уходят по одной в configure terminal; ответ IOS с «% ...»
        (Invalid input, Incomplete и т. п.) останавливает подготовку. После
        отправки hostname и ip address сверяются с running-config (плюс
        строки из expect). В конце подготовки — write memory и очистка
        истории консоли; reload=True — ещё и перезагрузка узла.
        Интерактивные команды (с вопросами) не поддерживаются, banner — одной
        строкой: banner motd #текст#.
    await ctx.cisco_show(узел, 'show ...') — вывод команды

    ctx.username, ctx.lab_stem

    Любая неудача (команда не прошла, узел не отвечает, тип узла пока не
    поддерживается) останавливает подготовку: студент видит узел, шаг и
    хвост вывода. Действия можно повторять: повторная подготовка безопасна.
    """

    def __init__(self, v, ostype, exec_fn, username='', lab_stem='', console_fn=None):
        self.v = v
        self.ostype = dict(ostype)
        self.nodes = sorted(self.ostype)
        self.username, self.lab_stem = username, lab_stem
        self._exec = exec_fn         # async (node, cmd) -> (rc, out, err)
        self._console = console_fn   # async (node) -> сессия консоли | str-ошибка
        self.touched = []            # узлы, на которых что-то настраивали
        self.reload_nodes = set()    # Cisco-узлы, которые перезагрузить в конце

    def _family(self, node, step, need):
        if node not in self.ostype:
            raise PrepareError(node, step, 'такого узла нет в лабе', teacher=True)
        fam = OS_FAMILY.get(self.ostype[node])
        if fam != need:
            if fam is None:
                detail = f'подготовка узлов типа «{self.ostype[node]}» пока не поддерживается'
            else:
                detail = f'это действие не для узлов типа «{self.ostype[node]}»'
            raise PrepareError(node, step, detail, teacher=True)
        return fam

    def _touch(self, node):
        if node not in self.touched:
            self.touched.append(node)

    async def _run(self, node, step, cmd):
        self._family(node, step, 'linux')
        rc, out, err = await self._exec(node, cmd)
        if rc is None:
            raise PrepareError(node, step, err or 'узел не отвечает (возможно, ещё загружается)')
        if rc != 0:
            raise PrepareError(node, step, f'код {rc}: ' + (_tail(err) or _tail(out) or 'без вывода'))
        self._touch(node)
        return out

    async def _open_console(self, node, step):
        self._family(node, step, 'cisco')
        if self._console is None:
            raise PrepareError(node, step, 'консоль недоступна')
        sess = await self._console(node)
        if isinstance(sess, str):
            raise PrepareError(node, step, sess)
        return sess

    # ------------------------------------------------------------ Linux
    async def shell(self, node, cmd, step=None):
        return await self._run(node, step or f'команда «{cmd[:60]}»', cmd)

    async def set_ip(self, node, iface, addr, gw=None, dns=None):
        if not _IFACE_RE.match(str(iface)):
            raise PrepareError(node, 'адрес', f'недопустимое имя интерфейса {iface!r}', teacher=True)
        cidr = addr.cidr if isinstance(addr, Addr) else str(addr)
        ipaddress.ip_interface(cidr)          # ValueError на явную опечатку
        if '/' not in cidr:
            raise PrepareError(node, 'адрес', f'у адреса {cidr} нет префикса (нужно вида 10.1.1.10/24)',
                               teacher=True)
        await self._run(node, f'адрес {cidr} на {iface}',
                        linux_set_ip_script(iface, cidr, gw=gw, dns=dns))

    async def set_hostname(self, node, name):
        name = str(name)
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9\-.]*$', name):
            raise PrepareError(node, 'имя узла', f'недопустимое имя {name!r}', teacher=True)
        q = shlex.quote(name)
        await self._run(node, f'имя узла {name}', '\n'.join([
            'set -e',
            f'hostnamectl set-hostname {q} 2>/dev/null || {{ echo {q} > /etc/hostname; hostname {q}; }}',
            "sed -i '/^127\\.0\\.1\\.1[[:space:]]/d' /etc/hosts",
            f"printf '127.0.1.1\\t%s\\n' {q} >> /etc/hosts",
        ]))

    async def mkdir(self, node, path):
        await self._run(node, f'каталог {path}', f'mkdir -p {shlex.quote(str(path))}')

    async def write_file(self, node, path, content, mode=None):
        await self._run(node, f'файл {path}', _write_cmd(str(path), content, mode))

    # ------------------------------------------------------------ Cisco
    async def cisco_config(self, node, text, reload=False, expect=()):
        lines = cisco_config_lines(text)
        step = 'конфигурация'
        sess = await self._open_console(node, step)
        try:
            bad = await sess.configure(lines)
            if bad:
                line, detail = bad
                # Строку не принял IOS (опечатка, интерактивная команда) —
                # это файл лабы, повтор студентом не поможет
                raise PrepareError(node, f'конфиг, строка: {line}', detail, teacher=True)
            running = _norm_ws(await sess.exec('show running-config'))
            need = cisco_verify_lines(lines) + [str(e) for e in expect]
            missing = [l for l in need if _norm_ws(l) not in running]
            if missing:
                raise PrepareError(node, 'сверка конфигурации',
                                   'в running-config нет строк: ' + '; '.join(missing[:5]),
                                   hint='Похоже, во время подготовки кто-то работал в консоли узла. '
                                        'Закройте консоли узлов и нажмите «Подготовить лабу» снова.')
        except ConsoleError as e:
            raise PrepareError(node, step, str(e))
        finally:
            await sess.close()
        self._touch(node)
        if reload:
            self.reload_nodes.add(node)

    async def cisco_show(self, node, cmd):
        step = f'команда «{cmd[:60]}»'
        sess = await self._open_console(node, step)
        try:
            return await sess.exec(cmd)
        except ConsoleError as e:
            raise PrepareError(node, step, str(e))
        finally:
            await sess.close()

    # ------------------------------------------------------------ метка подготовки
    async def write_marker(self, node, token):
        """Метка с отпечатком варианта. Для Cisco — alias exec в конфиге, после
        неё write memory, очистка истории консоли и, если просили, reload."""
        fam = OS_FAMILY.get(self.ostype.get(node))
        if fam == 'linux':
            await self._run(node, 'метка подготовки', _write_cmd(MARKER_PATH, token + '\n', 0o644))
            return
        step = 'сохранение конфигурации'
        sess = await self._open_console(node, step)
        try:
            name = cisco_marker_name(token)
            old = [n for n in cisco_marker_names(await sess.exec(CISCO_MARKER_READ)) if n != name]
            bad = await sess.configure([f'no alias exec {n}' for n in old] + [cisco_marker_line(token)])
            if bad:
                raise PrepareError(node, step, f'{bad[0]}: {bad[1]}')
            # Метку сразу читаем обратно: если IOS её не принял (молча), это
            # должно быть видно сейчас, а не «сбросом узла» при проверке
            got = await sess.exec(CISCO_MARKER_READ)
            if name not in cisco_marker_names(got):
                raise PrepareError(node, 'метка подготовки',
                                   f'строка «{cisco_marker_line(token)}» не появилась в running-config; '
                                   f'ответ: {" ".join(got.split())[:200] or "пусто"}', teacher=True)
            err = await sess.save()
            if err:
                raise PrepareError(node, step, err)
            await sess.clear_history()
            if node in self.reload_nodes:
                await sess.reload()
        except ConsoleError as e:
            raise PrepareError(node, step, str(e))
        finally:
            await sess.close()

    async def has_marker(self, node, token):
        """(есть ли на узле метка этой подготовки, сырой ответ узла).
        Первый элемент None — узел не ответил."""
        fam = OS_FAMILY.get(self.ostype.get(node))
        if fam == 'linux':
            rc, out, err = await self._exec(node, MARKER_READ_CMD)
            return (None if rc is None else out.strip() == token), (out if rc is not None else err)
        if fam == 'cisco' and self._console is not None:
            sess = await self._console(node)
            if isinstance(sess, str):
                return None, sess
            try:
                out = await sess.exec(CISCO_MARKER_READ)
                return cisco_marker_name(token) in cisco_marker_names(out), out
            except ConsoleError as e:
                return None, str(e)
            finally:
                await sess.close()
        return False, 'узел этого типа не поддерживается'


MARKER_READ_CMD = f'cat {MARKER_PATH} 2>/dev/null || true'


# ================================================================== предпросмотр

# Что подставляется в файл лабы без импорта (VARIANT пишется как есть)
BUILDERS = {'net': net, 'nets': nets, 'subnets': subnets, 'host_in': host_in,
            'choice': choice, 'number': number, 'text': text,
            'PrepareError': PrepareError}


def load_module(path):
    """Читает и исполняет файл лабы заново (без кеша), с BUILDERS в
    пространстве имён."""
    import types
    module = types.ModuleType('lab_' + re.sub(r'\W', '_', path))
    module.__file__ = path
    module.__dict__.update(BUILDERS)
    with open(path, encoding='utf-8') as f:
        exec(compile(f.read(), path, 'exec'), module.__dict__)
    return module


def _main(argv):
    import os
    if len(argv) < 3:
        print('usage: python3 labprep.py /pnet/checks/<лаба>.py логин [логин ...]')
        return 2
    path = argv[1]
    stem = os.path.basename(path).rsplit('.', 1)[0]
    module = load_module(path)
    if not has_variant(module):
        print('в файле нет VARIANT / variant(v)')
        return 1
    for user in argv[2:]:
        v = make_variant(module, user, stem)
        print(f'== {user}  (метка {variant_token(v, stem)})')
        for k, val in variant_items(v):
            print(f'   {k:12} {val}')
        task = task_text(module, v)
        if task:
            print('   задание: ' + task.replace('\n', '\n            '))
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(_main(sys.argv))
