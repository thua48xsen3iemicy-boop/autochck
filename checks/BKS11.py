"""Лаба BKS11: подготовка (как ROAS) и доп. проверки SSH и коммутатора.

Лежит в /pnet/checks/BKS11.py (лаба BKS11.unl). В description лабы —
autocheck:on prepare:on.

Топология:
  RWAN, ADMIN1, BUH1, BUH2, MGR1, SALE1, SALE2 — Debian 12, ens3 по DHCP;
  у RWAN ens3 — адрес от оператора (на него студент заходит по ssh, он
  обязан получать адрес и шлюз по DHCP), ens4 — в Switch Gi0/0.
  Switch — vIOS-L2. Клиенты: ADMIN1 Gi1/2, BUH1 Gi1/1, BUH2 Gi1/0,
  MGR1 Gi0/3, SALE1 Gi0/2, SALE2 Gi0/1.

Подготовка (только Switch, Linux-узлы не трогаются) — та же, что в ROAS.py:
  - SSH для студента: cisco / cisco, сразу privilege 15 (hostname SW1,
    ip domain-name lab.local — без них IOS не создаёт ключ RSA);
  - Gi0/0 — транк dot1q (инкапсуляция явно до включения транка), в транке
    только VLAN 777; SVI Vlan777 10.77.7.1/24;
  - все остальные порты — shutdown.
SSH старого IOS (vIOS-L2) с Debian 12:
  ssh -o KexAlgorithms=+diffie-hellman-group14-sha1 \
      -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
      cisco@10.77.7.1

Доп. проверки (добавляются к основным, основные не обнуляются). Каждая
группа — пункт оценки «сколько верно из скольких», а каждая её ошибка ещё и
штраф ERROR_PENALTY баллов из общего итога:
  - ADMIN1: есть пользователь admin, у него пара ключей SSH (~/.ssh/id_* и
    id_*.pub);
  - на RWAN, BUH1, BUH2, MGR1, SALE1, SALE2 публичный ключ admin есть в
    authorized_keys root, с опцией from=, где указан адрес ADMIN1 (на RWAN —
    ещё и 10.0.103.2);
  - на тех же узлах вход root по паролю по SSH отключён (PermitRootLogin
    prohibit-password или пароли выключены вовсе; PermitRootLogin no —
    ошибка: тогда и ключ root не работает). Смотрится действующая
    настройка sshd -T, если её не получить — sshd_config;
  - Switch: description порта = имя подключённого узла (Gi0/0 — RWAN);
    VLAN узлов названы по подразделению (SALE1, SALE2 — SALE, ADMIN1 —
    ADMIN, BUH1, BUH2 — BUH, MGR1 — MGR); есть VLAN 333 с name mgmt и SVI
    Vlan333 с адресом (любым); VLAN 777 из подготовки и его SVI удалены.
"""

import asyncio
import re

SWITCH = 'Switch'
TRUNK_PORT = 'GigabitEthernet0/0'
MGMT_VLAN = 777
MGMT_IP = '10.77.7.1'
MGMT_MASK = '255.255.255.0'
HOSTNAME = 'SW1'
DOMAIN = 'lab.local'
SSH_USER, SSH_PASSWORD = 'cisco', 'cisco'

_PORT_RE = re.compile(r'^((?:GigabitEthernet|FastEthernet|Ethernet)\d+(?:/\d+)+)\s+.*?\s(administratively down|up|down)\s+(up|down)\s*$')


def switch_ports(brief):
    """{порт: состояние} физических портов из show ip interface brief."""
    ports = {}
    for line in brief.splitlines():
        m = _PORT_RE.match(line.strip())
        if m:
            ports[m.group(1)] = m.group(2)
    return ports


async def prepare(ctx):
    if ctx.skipped(SWITCH):
        return      # коммутатор уже подготовлен (метка на месте) — не трогаем
    ports = switch_ports(await ctx.cisco_show(SWITCH, 'show ip interface brief'))
    if TRUNK_PORT not in ports:
        raise PrepareError(SWITCH, 'список портов',
                           f'на коммутаторе нет порта {TRUNK_PORT} (найдено: {", ".join(ports) or "ничего"})',
                           teacher=True)
    others = [p for p in ports if p != TRUNK_PORT]
    has_key = 'Key name' in await ctx.cisco_show(SWITCH, 'show crypto key mypubkey rsa')

    config = [
        f'hostname {HOSTNAME}',
        f'ip domain-name {DOMAIN}',
        f'username {SSH_USER} privilege 15 secret {SSH_PASSWORD}',
    ]
    if not has_key:
        config.append('crypto key generate rsa modulus 2048')
    config += [
        'ip ssh version 2',
        'line vty 0 4',
        ' login local',
        ' transport input ssh',
        f'vlan {MGMT_VLAN}',
        f'interface {TRUNK_PORT}',
        ' switchport trunk encapsulation dot1q',
        ' switchport mode trunk',
        f' switchport trunk allowed vlan {MGMT_VLAN}',
        ' no shutdown',
        f'interface Vlan{MGMT_VLAN}',
        f' ip address {MGMT_IP} {MGMT_MASK}',
        ' no shutdown',
    ]
    for port in others:
        config += [f'interface {port}', ' shutdown']

    await ctx.cisco_config(SWITCH, '\n'.join(config), expect=[
        f'username {SSH_USER} privilege 15',
        'ip ssh version 2',
        'login local',
        'transport input ssh',
        'switchport trunk encapsulation dot1q',
        'switchport mode trunk',
        f'switchport trunk allowed vlan {MGMT_VLAN}',
    ])

    ssh = await ctx.cisco_show(SWITCH, 'show ip ssh')
    if 'SSH Enabled' not in ssh:
        raise PrepareError(SWITCH, 'SSH', 'SSH не включился: ' + ' '.join(ssh.split())[:200], teacher=True)

    # Порты: все, кроме транка, выключены; транк не выключен
    state = switch_ports(await ctx.cisco_show(SWITCH, 'show ip interface brief'))
    still_on = [p for p in others if state.get(p) != 'administratively down']
    if still_on or state.get(TRUNK_PORT) == 'administratively down':
        raise PrepareError(SWITCH, 'сверка портов',
                           'не выключены: ' + ', '.join(still_on) if still_on else f'{TRUNK_PORT} выключен',
                           hint='Похоже, во время подготовки кто-то работал в консоли коммутатора. '
                                'Закройте консоли узлов и нажмите «Подготовить лабу» снова.')


# ================================================================== доп. проверки

ERROR_PENALTY = 5           # штраф за каждую ошибку доп. проверок (баллов)
ADMIN_NODE = 'ADMIN1'
ADMIN_USER = 'admin'
KEY_NODES = ['RWAN', 'BUH1', 'BUH2', 'MGR1', 'SALE1', 'SALE2']
EXTRA_FROM = {'RWAN': ['10.0.103.2']}     # кроме адреса ADMIN1
# Узел -> порт коммутатора
NODE_PORTS = {
    'RWAN': 'GigabitEthernet0/0',
    'ADMIN1': 'GigabitEthernet1/2',
    'BUH1': 'GigabitEthernet1/1',
    'BUH2': 'GigabitEthernet1/0',
    'MGR1': 'GigabitEthernet0/3',
    'SALE1': 'GigabitEthernet0/2',
    'SALE2': 'GigabitEthernet0/1',
}
MGMT_NEW_VLAN, MGMT_NEW_NAME = 333, 'mgmt'

L_USER = 'ADMIN1: пользователь admin с ключами SSH'
L_KEY = 'Ключ admin в authorized_keys root'
L_FROM = 'Опция from= для ключа admin'
L_ROOTPW = 'Вход root по паролю (SSH) отключён'
L_DESC = 'Описания портов коммутатора'
L_VNAME = 'Имена VLAN подразделений'
L_MGMT = 'VLAN управления 333 (mgmt)'
L_777 = 'VLAN 777 из подготовки удалён'

ADMIN_SCRIPT = r"""
echo '==USER'
getent passwd admin
H=$(getent passwd admin | cut -d: -f6)
echo '==KEYS'
if [ -n "$H" ]; then
  for f in "$H"/.ssh/id_*; do
    [ -f "$f" ] || continue
    case "$f" in
      *.pub) printf 'PUB %s %s\n' "${f%.pub}" "$(head -n1 "$f")" ;;
      *) printf 'PRIV %s\n' "$f" ;;
    esac
  done
fi
echo '==ADDR'
ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}'
echo '==END'
"""

NODE_SCRIPT = r"""
echo '==AK'
cat /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 2>/dev/null
echo '==SSHD'
S=$(command -v sshd || echo /usr/sbin/sshd)
"$S" -T 2>/dev/null | grep -iE '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication) '
echo '==SSHDCONF'
cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \
  | grep -iE '^[[:space:]]*(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|match)[[:space:]]'
echo '==END'
"""


def sections(out):
    """'==NAME' ... -> {NAME: [строки]}"""
    res, cur = {}, None
    for line in (out or '').splitlines():
        if line.startswith('==') and line[2:].strip().isupper():
            cur = line[2:].strip()
            res[cur] = []
        elif cur:
            res[cur].append(line)
    return res


def split_key_line(line):
    """Строка authorized_keys -> (опции, тип, ключ) или None. Опции — первое
    поле, если оно не тип ключа; кавычки внутри опций учитываются."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    fields, cur, quoted = [], '', False
    for ch in line:
        if ch == '"':
            quoted = not quoted
        if ch in ' \t' and not quoted:
            if cur:
                fields.append(cur)
                cur = ''
            continue
        cur += ch
    if cur:
        fields.append(cur)
    key_types = re.compile(r'^(ssh-|ecdsa-|sk-)')
    if len(fields) >= 2 and key_types.match(fields[0]):
        return '', fields[0], fields[1]
    if len(fields) >= 3 and key_types.match(fields[1]):
        return fields[0], fields[1], fields[2]
    return None


def from_patterns(options):
    """Список адресов/шаблонов из from="..." в опциях ключа."""
    m = re.search(r'(?:^|,)from="([^"]*)"', options or '', re.IGNORECASE)
    return [p.strip() for p in m.group(1).split(',')] if m else None


def root_password_login(conf):
    """(отключён ли вход root по паролю, пояснение) по словарю настроек sshd."""
    prl = conf.get('permitrootlogin', 'prohibit-password')
    if prl == 'no':
        return False, 'PermitRootLogin no — root не войдёт и по ключу'
    if prl in ('prohibit-password', 'without-password', 'forced-commands-only'):
        return True, ''
    if conf.get('passwordauthentication', 'yes') == 'no' and conf.get('kbdinteractiveauthentication', 'yes') == 'no':
        return True, ''
    return False, f'PermitRootLogin {prl}, пароли не выключены'


def sshd_settings(sec):
    """Действующие настройки sshd: из sshd -T, иначе первое вхождение в
    sshd_config.d/*.conf и sshd_config (до первого Match)."""
    conf = {}
    for line in sec.get('SSHD', []):
        parts = line.split()
        if len(parts) >= 2:
            conf[parts[0].lower()] = parts[1].lower()
    if conf:
        return conf, True
    for line in sec.get('SSHDCONF', []):
        parts = line.split()
        if not parts:
            continue
        key = parts[0].lower()
        if key == 'match':
            break
        if key == 'challengeresponseauthentication':
            key = 'kbdinteractiveauthentication'
        if len(parts) >= 2:
            conf.setdefault(key, parts[1].lower())
    return conf, False


def short_port(name):
    for full, short in (('GigabitEthernet', 'Gi'), ('FastEthernet', 'Fa'), ('Ethernet', 'Et')):
        if name.startswith(full):
            return short + name[len(full):]
    return name


def ios_blocks(running):
    """running-config -> {'interface Gi...': [строки блока]}"""
    blocks, cur = {}, None
    for line in (running or '').splitlines():
        if not line.strip() or line.strip() == '!':
            continue
        if not line.startswith(' '):
            cur = line.strip()
            blocks.setdefault(cur, [])
        elif cur:
            blocks[cur].append(line.strip())
    return blocks


def vlan_brief(out):
    """show vlan brief -> {номер: {'name', 'ports': [Gi0/1, ...]}}"""
    vlans, last = {}, None
    for line in (out or '').splitlines():
        m = re.match(r'^(\d+)\s+(\S+)\s+(\S+)\s*(.*)$', line)
        if m and re.match(r'^(active|act/|sus)', m.group(3)):
            last = int(m.group(1))
            vlans[last] = {'name': m.group(2), 'ports': re.findall(r'[A-Za-z]+\d+(?:/\d+)+', m.group(4))}
        elif last is not None and re.match(r'^\s+[A-Za-z]+\d', line):
            vlans[last]['ports'] += re.findall(r'[A-Za-z]+\d+(?:/\d+)+', line)
    return vlans


def department(node):
    return re.sub(r'\d+$', '', node).upper()


class Group:
    """Группа доп. проверки: элементы ok/ошибка, итог — add_check + штраф."""

    def __init__(self, ctx, label):
        self.ctx, self.label, self.good, self.total = ctx, label, 0, 0

    def item(self, ok, msg=None):
        self.total += 1
        if ok:
            self.good += 1
        elif msg:
            self.ctx.error(msg)

    def done(self):
        self.ctx.add_check(self.label, self.good, self.total)
        self.ctx.penalty(f'{self.label} — ошибки', self.total - self.good, ERROR_PENALTY)


async def check_linux(ctx):
    nodes = [ADMIN_NODE] + KEY_NODES
    outs = await asyncio.gather(ctx.run(ADMIN_NODE, ADMIN_SCRIPT),
                                *(ctx.run(n, NODE_SCRIPT) for n in KEY_NODES))
    res = dict(zip(nodes, outs))

    # ADMIN1: пользователь и пара ключей
    g = Group(ctx, L_USER)
    sec = sections(res[ADMIN_NODE])
    reachable = res[ADMIN_NODE] != 'NONE' and 'END' in sec
    user_ok = reachable and any(l.startswith(ADMIN_USER + ':') for l in sec.get('USER', []))
    g.item(user_ok, f'{ADMIN_NODE}: нет пользователя {ADMIN_USER}' if reachable else
           f'{ADMIN_NODE}: узел не ответил — пользователь и ключи не проверены')
    privs = {l.split(None, 1)[1].strip() for l in sec.get('KEYS', []) if l.startswith('PRIV ')}
    blobs = []
    for l in sec.get('KEYS', []):
        if l.startswith('PUB '):
            parts = l.split()
            if len(parts) >= 4 and parts[1] in privs:
                blobs.append(parts[3])
    g.item(bool(blobs), f'{ADMIN_NODE}: у {ADMIN_USER} нет пары ключей SSH (~/.ssh/id_* и id_*.pub)'
           if user_ok else None)
    g.done()

    admin_ip = None
    for l in sec.get('ADDR', []):
        parts = l.split()
        if len(parts) == 2 and (admin_ip is None or parts[0] == 'ens3'):
            admin_ip = parts[1].split('/')[0]

    gk, gf, gp = Group(ctx, L_KEY), Group(ctx, L_FROM), Group(ctx, L_ROOTPW)
    for node in KEY_NODES:
        s = sections(res[node])
        if res[node] == 'NONE' or 'END' not in s:
            ctx.error(f'{node}: узел не ответил — ключи и настройки SSH не проверены')
            for grp in (gk, gf, gp):
                grp.item(False)
            continue
        entry = None
        for line in s.get('AK', []):
            parsed = split_key_line(line)
            if parsed and parsed[2] in blobs:
                entry = parsed
                break
        if not blobs:
            gk.item(False, f'{node}: нечего искать в authorized_keys root — у {ADMIN_USER} на {ADMIN_NODE} нет ключа')
        else:
            gk.item(entry is not None, f'{node}: ключа {ADMIN_USER}@{ADMIN_NODE} нет в /root/.ssh/authorized_keys')
        if entry is None:
            gf.item(False)
        else:
            pats = from_patterns(entry[0])
            need = ([admin_ip] if admin_ip else []) + EXTRA_FROM.get(node, [])
            if pats is None:
                gf.item(False, f'{node}: у ключа {ADMIN_USER} в authorized_keys root нет опции from=')
            elif not admin_ip:
                gf.item(False, f'{node}: не удалось узнать адрес {ADMIN_NODE} — from= не проверен')
            else:
                missing = [a for a in need if a not in pats]
                gf.item(not missing, f'{node}: в from="{",".join(pats)}" нет {", ".join(missing)}')
        conf, _effective = sshd_settings(s)
        ok, why = root_password_login(conf)
        gp.item(ok, f'{node}: вход root по паролю по SSH не отключён ({why})' if not ok else None)
    for grp in (gk, gf, gp):
        grp.done()


async def check_switch(ctx):
    running, brief = await ctx.cisco_show(SWITCH, ['show running-config', 'show vlan brief'])
    gd, gv, gm, g7 = Group(ctx, L_DESC), Group(ctx, L_VNAME), Group(ctx, L_MGMT), Group(ctx, L_777)
    if running == 'NONE' or brief == 'NONE':
        ctx.error(f'{SWITCH}: нет доступа к консоли коммутатора — его настройки не проверены')
        for _ in NODE_PORTS:
            gd.item(False)
        for _ in range(len(NODE_PORTS) - 1):
            gv.item(False)
        for grp in (gm, gm, g7, g7):
            grp.item(False)
    else:
        blocks = ios_blocks(running)
        vlans = vlan_brief(brief)
        for node, port in NODE_PORTS.items():
            body = blocks.get(f'interface {port}', [])
            desc = next((l[len('description '):].strip() for l in body if l.startswith('description ')), None)
            gd.item(desc is not None and desc.lower() == node.lower(),
                    f'{SWITCH} {short_port(port)}: description «{desc or "нет"}», должно быть {node}')
        for node, port in NODE_PORTS.items():
            if node == 'RWAN':
                continue      # транк
            vid = next((v for v, info in vlans.items() if short_port(port) in info['ports']), None)
            want = department(node)
            if vid is None:
                gv.item(False, f'{SWITCH} {short_port(port)} ({node}): порт не в access VLAN')
            else:
                name = vlans[vid]['name']
                gv.item(name.upper() == want, f'{SWITCH}: VLAN {vid} узла {node} назван «{name}», должно быть {want}')
        mv = vlans.get(MGMT_NEW_VLAN)
        gm.item(mv is not None and mv['name'].lower() == MGMT_NEW_NAME,
                f'{SWITCH}: нет VLAN {MGMT_NEW_VLAN}' if mv is None else
                f'{SWITCH}: VLAN {MGMT_NEW_VLAN} назван «{mv["name"]}», должно быть {MGMT_NEW_NAME}')
        svi = blocks.get(f'interface Vlan{MGMT_NEW_VLAN}')
        has_ip = svi is not None and any(re.match(r'^ip address \d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+', l) for l in svi)
        gm.item(has_ip and 'shutdown' not in svi,
                f'{SWITCH}: нет интерфейса Vlan{MGMT_NEW_VLAN}' if svi is None else
                f'{SWITCH}: у Vlan{MGMT_NEW_VLAN} нет адреса' if not has_ip else
                f'{SWITCH}: Vlan{MGMT_NEW_VLAN} выключен (shutdown)')
        g7.item(MGMT_VLAN not in vlans, f'{SWITCH}: VLAN {MGMT_VLAN} из подготовки не удалён')
        g7.item(f'interface Vlan{MGMT_VLAN}' not in blocks, f'{SWITCH}: интерфейс Vlan{MGMT_VLAN} не удалён')
    for grp in (gd, gv, gm, g7):
        grp.done()


async def check(ctx):
    await check_linux(ctx)
    await check_switch(ctx)
