"""GIT1: преднастрой сети Debian (ifupdown) и проверка hostname/Git.

Установка: /pnet/checks/GIT1.py для GIT1.unl; в description лабы добавить
autocheck:on prepare:on. Все узлы запускаются перед подготовкой.

ROUTER: ens3 — DHCP, ens4 — 10.10.1.254/24; IPv4 forwarding и nftables
masquerade через ens3. Git1/Git2/Git3: ens3 — 10.10.1.1/2/3 с префиксом /24,
шлюз 10.10.1.254. Коммутатор не настраивается.
Имена узлов в топологии должны совпадать с NODES; имя роутера задаёт ROUTER.

Подготовка заменяет interfaces и nftables.conf (на роутере), сохраняет
резервные копии, применяет настройки и сверяет адреса/шлюзы. Сетевой лог:
/var/log/git1-prep.log. Повторная подготовка пропускает узлы с меткой.
Подготовка задаёт только адреса и шлюзы, форвардинг и NAT на ROUTER.
DNS не настраивается. Hostname, Git и SSH студент настраивает сам.

Оценка по отдельным пунктам, без дополнительных штрафов:
- hostname на всех четырёх узлах: текущее и /etc/hostname; регистр не важен,
  FQDN допускается (сравнивается первая часть);
- пакет git установлен и git --version работает на Git1, Git2, Git3.
Дополнительно проверяется SSH-конфигурация root на ROUTER: Git1–Git3
разрешаются в адреса из NODES, User root, IdentityFile указывает на общий
отдельный ключ (не стандартный id_rsa/id_ed25519 и т. п.). Include учитывается
самим OpenSSH через ssh -G. Ключ должен читаться без интерактивного ввода
пароля; его публичная часть извлекается ssh-keygen -y, приватная не выводится.
На каждом Git-узле этот ключ должен быть в /root/.ssh/authorized_keys.
SSH-конфигурацию и ключи создаёт студент, prepare их не меняет.
Не ответивший или отсутствующий узел не получает баллы за свои проверки.
"""

import asyncio
import re
import shlex

ONLY_EXTRA = True
KEEP = []
CHECK_STATIC = True
ROUTER = 'ROUTER'
WAN = 'ens3'
GIT_NODES = ('Git1', 'Git2', 'Git3')
NODES = {
    ROUTER: [('ens3', 'dhcp', None), ('ens4', '10.10.1.254/24', None)],
    'Git1': [('ens3', '10.10.1.1/24', '10.10.1.254')],
    'Git2': [('ens3', '10.10.1.2/24', '10.10.1.254')],
    'Git3': [('ens3', '10.10.1.3/24', '10.10.1.254')],
}
IFACES_FILE = '/etc/network/interfaces'
IFACES_OLD = '/etc/network/interfaces.git1-old'
PREP_LOG = '/var/log/git1-prep.log'


def interfaces_text(node):
    lines = [f'# GIT1 — {node}', 'auto lo', 'iface lo inet loopback', '']
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

# Отдельная учебная топология: известный ruleset с разрешённым forwarding.
NFT_CONFIG = '''#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input { type filter hook input priority filter; policy accept; }
    chain forward { type filter hook forward priority filter; policy accept; }
    chain output { type filter hook output priority filter; policy accept; }
}
table ip git1_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 10.10.1.0/24 oifname "@WAN@" masquerade
    }
}
'''.replace('@WAN@', WAN)

NFT_BACKUP = '''
set -e
command -v nft >/dev/null
if [ -f /etc/nftables.conf ] && [ ! -f /etc/nftables.conf.git1-old ]; then
    cp /etc/nftables.conf /etc/nftables.conf.git1-old
fi
'''
NFT_APPLY = '''
set -e
nft -c -f /etc/nftables.conf
systemctl enable nftables >/dev/null 2>&1
systemctl restart nftables
nft list chain ip git1_nat postrouting | grep -Fq 'oifname "@WAN@" masquerade'
'''.replace('@WAN@', WAN)


async def prepare(ctx):
    for node in NODES:
        if ctx.skipped(node):
            continue
        await ctx.shell(node, backup_script(node), step='проверка интерфейсов')
        await ctx.write_file(node, IFACES_FILE, interfaces_text(node), mode=0o644)
        await ctx.shell(node, apply_script(node), step='применение сетевых настроек')
        if node == ROUTER:
            await ctx.shell(node, FORWARD_SCRIPT, step='форвардинг IPv4')
            await ctx.shell(node, NFT_BACKUP, step='резервная копия nftables')
            await ctx.write_file(node, '/etc/nftables.conf', NFT_CONFIG, mode=0o644)
            await ctx.shell(node, NFT_APPLY, step=f'NAT через {WAN} (nftables)')


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


GIT_CMD = r'''
if [ "$(dpkg-query -W -f='${Status}' git 2>/dev/null)" = 'install ok installed' ] \
   && git --version >/dev/null 2>&1; then
    echo GIT_INSTALLED
else
    echo GIT_MISSING
fi
'''


async def check(ctx):
    async def run(node, cmd):
        return await ctx.run(node, cmd) if node in ctx.ostype else 'NONE'

    nodes = list(NODES)
    hostnames = await asyncio.gather(*(run(n, HOSTNAME_CMD) for n in nodes))
    good = 0
    for node, out in zip(nodes, hostnames):
        errs = node_errors(node, out)
        good += not errs
        for err in errs:
            ctx.error(err)
    ctx.add_check('Имена узлов', good, len(nodes))

    installed = await asyncio.gather(*(run(n, GIT_CMD) for n in GIT_NODES))
    good = 0
    for node, out in zip(GIT_NODES, installed):
        if out.strip() == 'GIT_INSTALLED':
            good += 1
        elif out == 'NONE':
            ctx.error(f'{node}: узел не ответил, установка Git не проверена')
        else:
            ctx.error(f'{node}: пакет git не установлен или команда git --version не работает')
    ctx.add_check('Git установлен', good, len(GIT_NODES))
    await check_ssh(ctx)


# ssh -G читает ~/.ssh/config, системный ssh_config и рекурсивные Include,
# применяя настоящие правила приоритетов OpenSSH.
def ssh_probe(node):
    return r'''
conf=$(ssh -G @NODE@ 2>/dev/null) || exit 1
printf '%s\n' "$conf" | awk '$1 == "hostname" || $1 == "user" {print}'
printf '%s\n' "$conf" | sed -n 's/^identityfile //p' |
while IFS= read -r key; do
    case "$key" in
        "~/"*) key="/root/${key#??}" ;;
    esac
    key=$(printf '%s\n' "$key" | sed 's|%d|/root|g')
    case "$key" in
        /root/.ssh/id_rsa|/root/.ssh/id_dsa|/root/.ssh/id_ecdsa|/root/.ssh/id_ecdsa_sk|/root/.ssh/id_ed25519|/root/.ssh/id_ed25519_sk|/root/.ssh/id_xmss|none) continue ;;
    esac
    [ -f "$key" ] || continue
    pub=$(ssh-keygen -y -P '' -f "$key" </dev/null 2>/dev/null) || continue
    printf 'KEY %s\n' "$pub"
done
'''.replace('@NODE@', shlex.quote(node))


AUTH_KEYS_CMD = 'cat /root/.ssh/authorized_keys 2>/dev/null || true'
KEY_TYPE = re.compile(r'^(ssh-|ecdsa-|sk-)')


def public_keys(text):
    """Сравнивать тип и blob; комментарии и опции authorized_keys не мешают."""
    keys = set()
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        try:
            fields = shlex.split(line)
        except ValueError:
            continue
        # Ключ — в начале или после единого поля опций authorized_keys.
        for i in (0, 1):
            if len(fields) > i + 1 and KEY_TYPE.match(fields[i]):
                keys.add((fields[i], fields[i + 1]))
                break
    return keys


async def check_ssh(ctx):
    async def probe(node):
        if ROUTER not in ctx.ostype:
            return 'NONE'
        return await ctx.run(ROUTER, ssh_probe(node))

    outputs = await asyncio.gather(*(probe(n) for n in GIT_NODES))
    good, key_sets = 0, []
    for node, out in zip(GIT_NODES, outputs):
        fields = {}
        for line in out.splitlines():
            name, _, value = line.partition(' ')
            fields[name] = value.strip()
        expected = NODES[node][0][1].split('/')[0]
        ok = fields.get('hostname') == expected and fields.get('user') == 'root'
        if not ok:
            ctx.error(f'{ROUTER}: SSH для {node} должен задавать HostName {expected} и User root '
                      '(проверьте SSH config и Include)')
        good += ok
        keys = public_keys('\n'.join(line[4:] for line in out.splitlines() if line.startswith('KEY ')))
        key_sets.append(keys)
    ctx.add_check('SSH config на ROUTER', good, len(GIT_NODES))
    common = set.intersection(*key_sets)
    ctx.add_check('Отдельный общий ключ SSH на ROUTER', int(bool(common)), 1)
    if not common:
        ctx.error(f'{ROUTER}: для Git1–Git3 не найден общий отдельный IdentityFile '
                  'с доступным приватным ключом без пароля (стандартные ключи не засчитываются)')

    async def authorized(node):
        return await ctx.run(node, AUTH_KEYS_CMD) if node in ctx.ostype else 'NONE'

    outputs = await asyncio.gather(*(authorized(n) for n in GIT_NODES))
    good = 0
    for node, out in zip(GIT_NODES, outputs):
        ok = out != 'NONE' and bool(common & public_keys(out))
        good += ok
        if not ok:
            ctx.error(f'{node}: общий ключ ROUTER не подтверждён в /root/.ssh/authorized_keys '
                      '(нет ключа, узел не ответил или ключ ROUTER не найден)')
    ctx.add_check('Ключ ROUTER в authorized_keys root', good, len(GIT_NODES))
