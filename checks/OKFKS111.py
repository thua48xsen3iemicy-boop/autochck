"""Лаба OKFKS111: массовая смена имён узлов (hostname) на 15 Debian 12.

Цель лабы — показать студенту, что менять имена руками на каждом узле по
SSH долго и неинтересно (мотивация к массовой настройке). Поэтому узлов
много, а проверяются только имена, и проверка строгая.

Переименуйте файл под имя .unl лабы, если оно другое (OKFKS111.unl ->
OKFKS111.py), и положите в /pnet/checks. В description лабы —
autocheck:on prepare:on.

Топология (все узлы — Debian 12, ifupdown):
  ROUTER         ens3 — DHCP (адрес и маршрут по умолчанию от оператора),
                 ens4 — 10.9.0.254/24, ens5 — 10.0.0.254/24,
                 ens6 — 10.0.1.254/24; NAT (masquerade) через ens3,
                 net.ipv4.ip_forward=1
  10.9.0.0/24    ROOT-CA .1, HTTPD-SRV .2, GIT .3, REVERSE-PROXY .4
  10.0.0.0/24    Linux12 .1, Linux11 .2, Linux8 .3, Linux3 .4, Linux1 .5
  10.0.1.0/24    Linux10 .1, Linux7 .2, Linux2 .3, Linux15 .4, Linux9 .5
  Шлюз в каждой сети — .254 (ROUTER).

Подготовка (prepare), на каждом узле:
  - /etc/network/interfaces перезаписывается целиком (lo inet loopback и
    интерфейсы узла, без source interfaces.d), прежний файл сохраняется в
    /etc/network/interfaces.okfks111-old;
  - настройки сразу применяются: старая конфигурация снимается по прежнему
    файлу (DHCP отпускается), адреса и маршрут по умолчанию очищаются,
    затем ifup -a; после этого адреса и шлюз сверяются. Лог применения —
    /var/log/okfks111-prep.log;
  - на ROUTER, кроме того: в /etc/sysctl.conf включается
    net.ipv4.ip_forward=1 (раскомментируется или дописывается) и
    выполняется sysctl -p; в /etc/nftables.conf перед последней «}»
    добавляется цепочка postrouting с masquerade через ens3 (если
    маскарада там ещё нет), файл проверяется nft -c, служба nftables
    включается в автозагрузку и перезапускается.
Имена узлов подготовка не трогает: их меняет студент.

Проверка (check): у каждого узла имя должно совпадать с именем узла в лабе
(без учёта регистра; FQDN допускается, сравнивается часть до первой точки):
  - текущее имя (hostname);
  - сохранённое имя (/etc/hostname), чтобы оно пережило перезагрузку.
    Отключается флагом CHECK_STATIC = False.
Не ответивший узел считается ошибкой.

Оценка только по этому пункту (ONLY_EXTRA, KEEP пуст — встроенный
Hostnames не учитывается): пункт «Имена узлов» на 15 баллов (по баллу за
узел) плюс штраф PENALTY_PER_ERROR за каждую ошибку. При 15 узлах и штрафе 1:
  ошибок   процент   оценка
    0        100       5
    1         87       5
    2         73       4
    3         60       3
    4+       <=47      2
Сделать мягче: PENALTY_PER_ERROR = 0 (тогда 2 ошибки — 5, 3–4 — 4, 5–7 — 3).
"""

import asyncio

ONLY_EXTRA = True
KEEP = []                 # встроенный Hostnames заменён строгой проверкой ниже

CHECK_STATIC = True       # проверять ещё и /etc/hostname
PENALTY_PER_ERROR = 1     # штраф (баллы из итога) за каждый узел с неверным именем

WAN = 'ens3'              # внешний интерфейс ROUTER: DHCP и NAT

# узел: [(интерфейс, адрес или 'dhcp', шлюз или None), ...]
NODES = {
    'ROUTER': [
        ('ens3', 'dhcp', None),
        ('ens4', '10.9.0.254/24', None),
        ('ens5', '10.0.0.254/24', None),
        ('ens6', '10.0.1.254/24', None),
    ],
    'ROOT-CA':       [('ens3', '10.9.0.1/24', '10.9.0.254')],
    'HTTPD-SRV':     [('ens3', '10.9.0.2/24', '10.9.0.254')],
    'GIT':           [('ens3', '10.9.0.3/24', '10.9.0.254')],
    'REVERSE-PROXY': [('ens3', '10.9.0.4/24', '10.9.0.254')],
    'Linux12':       [('ens3', '10.0.0.1/24', '10.0.0.254')],
    'Linux11':       [('ens3', '10.0.0.2/24', '10.0.0.254')],
    'Linux8':        [('ens3', '10.0.0.3/24', '10.0.0.254')],
    'Linux3':        [('ens3', '10.0.0.4/24', '10.0.0.254')],
    'Linux1':        [('ens3', '10.0.0.5/24', '10.0.0.254')],
    'Linux10':       [('ens3', '10.0.1.1/24', '10.0.1.254')],
    'Linux7':        [('ens3', '10.0.1.2/24', '10.0.1.254')],
    'Linux2':        [('ens3', '10.0.1.3/24', '10.0.1.254')],
    'Linux15':       [('ens3', '10.0.1.4/24', '10.0.1.254')],
    'Linux9':        [('ens3', '10.0.1.5/24', '10.0.1.254')],
}

IFACES_FILE = '/etc/network/interfaces'
IFACES_OLD = '/etc/network/interfaces.okfks111-old'
PREP_LOG = '/var/log/okfks111-prep.log'


# ================================================================ подготовка

def interfaces_text(node):
    lines = [f'# OKFKS111 — {node}', 'auto lo', 'iface lo inet loopback', '']
    for iface, addr, gw in NODES[node]:
        lines.append(f'auto {iface}')
        if addr == 'dhcp':
            lines.append(f'iface {iface} inet dhcp')
        else:
            lines += [f'iface {iface} inet static', f'    address {addr}']
            if gw:
                lines.append(f'    gateway {gw}')
        lines.append('')
    return '\n'.join(lines)


def backup_script(node):
    """Проверить, что интерфейсы есть, и сохранить прежний interfaces."""
    ifaces = ' '.join(i for i, _a, _g in NODES[node])
    return '\n'.join([
        f'for i in {ifaces}; do',
        '  ip link show "$i" >/dev/null 2>&1 || { echo "на узле нет интерфейса $i"; exit 1; }',
        'done',
        f'cp {IFACES_FILE} {IFACES_OLD} 2>/dev/null || : > {IFACES_OLD}',
    ])


def apply_script(node):
    """Снять старую конфигурацию, поднять новую и сверить результат.

    Вывод ifdown/ifup идёт в лог, а не в канал guest-agent: dhclient
    уходит в фон, и держать открытым вывод команды ему нельзя."""
    ifaces = ' '.join(i for i, _a, _g in NODES[node])
    verify = []
    for iface, addr, gw in NODES[node]:
        if addr == 'dhcp':
            verify.append(f'ip -4 -o addr show dev {iface} | grep -q " inet " '
                          f'|| {{ echo "{iface} не получил адрес по DHCP"; bad=1; }}')
            verify.append('ip -4 route show default | grep -q . '
                          f'|| {{ echo "нет маршрута по умолчанию от DHCP ({iface})"; bad=1; }}')
        else:
            verify.append(f'ip -4 -o addr show dev {iface} | grep -q " {addr} " '
                          f'|| {{ echo "на {iface} нет адреса {addr}"; bad=1; }}')
        if gw:
            verify.append(f'ip -4 route show default | grep -q "via {gw} " '
                          f'|| {{ echo "нет маршрута по умолчанию через {gw}"; bad=1; }}')
    return '\n'.join([
        '(',
        f'  ifdown -a --force --exclude=lo -i {IFACES_OLD} || true',
        '  pkill -x dhclient || true',
        f'  for i in {ifaces}; do ip -4 addr flush dev "$i"; done',
        '  while ip -4 route del default 2>/dev/null; do :; done',
        '  ifup -a --force',
        f') >{PREP_LOG} 2>&1',
        'rc=$?',
        'bad=0',
        *verify,
        f'if [ "$rc" -ne 0 ] || [ "$bad" -ne 0 ]; then tail -n 15 {PREP_LOG}; exit 1; fi',
    ])


# Форвардинг: раскомментировать строку ip_forward или дописать её
FORWARD_SCRIPT = r'''
SYS=/etc/sysctl.conf
touch "$SYS"
if grep -qE '^[[:space:]]*#?[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' "$SYS"; then
  sed -i -E 's/^[[:space:]]*#?[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*/net.ipv4.ip_forward=1/' "$SYS"
else
  echo 'net.ipv4.ip_forward=1' >> "$SYS"
fi
sysctl -p >/dev/null 2>&1 || true
[ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || { echo 'net.ipv4.ip_forward не включился'; exit 1; }
'''

# NAT: цепочка postrouting с masquerade перед последней «}» nftables.conf
NAT_SCRIPT = r'''
set -e
NFT=/etc/nftables.conf
BLK=$(mktemp)
printf '\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname "%s" masquerade\n\t}\n' '@WAN@' > "$BLK"
[ -f "$NFT" ] && [ ! -f "$NFT.okfks111-old" ] && cp "$NFT" "$NFT.okfks111-old"
if [ -f "$NFT" ] && grep -q 'masquerade' "$NFT"; then
  :
elif [ -f "$NFT" ] && grep -qE '^[[:space:]]*}[[:space:]]*$' "$NFT"; then
  awk 'NR==FNR { blk = blk $0 "\n"; next }
       { line[++n] = $0; if ($0 ~ /^[[:space:]]*}[[:space:]]*$/) last = n }
       END { for (i = 1; i <= n; i++) { if (i == last) printf "%s", blk; print line[i] } }' \
      "$BLK" "$NFT" > "$NFT.new"
  cat "$NFT.new" > "$NFT"; rm -f "$NFT.new"
else
  {
    printf '#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {\n'
    printf '\tchain input {\n\t\ttype filter hook input priority filter;\n\t}\n'
    printf '\tchain forward {\n\t\ttype filter hook forward priority filter;\n\t}\n'
    printf '\tchain output {\n\t\ttype filter hook output priority filter;\n\t}\n'
    cat "$BLK"
    printf '}\n'
  } > "$NFT"
fi
rm -f "$BLK"
nft -c -f "$NFT"
systemctl enable nftables >/dev/null 2>&1
systemctl restart nftables
nft list ruleset | grep -q 'oifname "@WAN@" masquerade' || { echo 'правило masquerade не загрузилось'; exit 1; }
'''.replace('@WAN@', WAN)


async def prepare(ctx):
    for node in NODES:
        if node == 'ROUTER':
            await ctx.shell(node, FORWARD_SCRIPT, step='форвардинг IPv4')
            await ctx.shell(node, NAT_SCRIPT, step=f'NAT через {WAN} (nftables)')
        await ctx.shell(node, backup_script(node), step='проверка интерфейсов')
        await ctx.write_file(node, IFACES_FILE, interfaces_text(node), mode=0o644)
        await ctx.shell(node, apply_script(node), step='применение сетевых настроек')


# ================================================================ проверка

HOSTNAME_CMD = 'hostname; echo ===; head -n 1 /etc/hostname 2>/dev/null'


def short(name):
    return name.strip().split('.')[0].lower()


def node_errors(node, out):
    """Список претензий к имени узла (пустой — всё верно)."""
    if out == 'NONE' or '===' not in out:
        return [f'{node}: узел не ответил, имя не проверено']
    cur, _, static = out.partition('===')
    cur, static = cur.strip(), static.strip()
    errs = []
    if short(cur) != node.lower():
        errs.append(f'{node}: имя узла «{cur or "пусто"}», должно быть {node}')
    elif CHECK_STATIC and short(static) != node.lower():
        errs.append(f'{node}: имя не сохранено — в /etc/hostname «{static or "пусто"}», '
                    'после перезагрузки вернётся старое')
    return errs


async def check(ctx):
    nodes = list(NODES)
    outs = await asyncio.gather(*(ctx.run(n, HOSTNAME_CMD) if n in ctx.ostype
                                  else asyncio.sleep(0, 'NONE') for n in nodes))
    bad = 0
    for node, out in zip(nodes, outs):
        errs = node_errors(node, out)
        if errs:
            bad += 1
            for e in errs:
                ctx.error(e)
    ctx.add_check('Имена узлов', len(nodes) - bad, len(nodes))
    if PENALTY_PER_ERROR:
        ctx.penalty('Имена узлов — штраф', bad, PENALTY_PER_ERROR)
