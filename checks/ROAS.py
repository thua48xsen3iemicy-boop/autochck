"""Подготовка лабы «роутер на палочке» (router-on-a-stick).

Переименуйте файл под имя .unl лабы (KS24.unl -> KS24.py) и положите в
/pnet/checks. В description лабы — autocheck:on prepare:on.

Топология:
  RWAN, ADMIN1, BUH1, BUH2, MGR1, SALE1, SALE2 — Debian 12, ens3 по DHCP;
  у RWAN ens3 — адрес от оператора (на него студент заходит по ssh, он
  обязан получать адрес и шлюз по DHCP), ens4 — в Switch Gi0/0.
  Switch — vIOS-L2. Клиенты: ADMIN1 Gi1/2, BUH1 Gi1/1, BUH2 Gi1/0,
  MGR1 Gi0/3, SALE1 Gi0/2, SALE2 Gi0/1.

Подготовка (только Switch, Linux-узлы не трогаются):
  - Gi0/0 — транк dot1q (инкапсуляция задаётся явно до включения транка),
    в транке разрешён только VLAN 777;
  - VLAN 777 и его SVI 10.77.7.1/24 (адрес студент знает из задания);
  - все остальные порты коммутатора — shutdown. Список портов берётся с
    самого коммутатора (show ip interface brief), так что подходит и для
    vIOS-L2 с 8, и с 16 портами.
После отправки конфиг сверяется: строки транка и SVI — с running-config,
состояние портов — с show ip interface brief.

Доп. проверок у лабы в этом файле нет (только prepare) — проверяется
обычными проверками автопроверки.
"""

import re

SWITCH = 'Switch'
TRUNK_PORT = 'GigabitEthernet0/0'
MGMT_VLAN = 777
MGMT_IP = '10.77.7.1'
MGMT_MASK = '255.255.255.0'

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
    ports = switch_ports(await ctx.cisco_show(SWITCH, 'show ip interface brief'))
    if TRUNK_PORT not in ports:
        raise PrepareError(SWITCH, 'список портов',
                           f'на коммутаторе нет порта {TRUNK_PORT} (найдено: {", ".join(ports) or "ничего"})',
                           teacher=True)
    others = [p for p in ports if p != TRUNK_PORT]

    config = [
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
        'switchport trunk encapsulation dot1q',
        'switchport mode trunk',
        f'switchport trunk allowed vlan {MGMT_VLAN}',
    ])

    # Порты: все, кроме транка, выключены; транк не выключен
    state = switch_ports(await ctx.cisco_show(SWITCH, 'show ip interface brief'))
    still_on = [p for p in others if state.get(p) != 'administratively down']
    if still_on or state.get(TRUNK_PORT) == 'administratively down':
        raise PrepareError(SWITCH, 'сверка портов',
                           'не выключены: ' + ', '.join(still_on) if still_on else f'{TRUNK_PORT} выключен',
                           hint='Похоже, во время подготовки кто-то работал в консоли коммутатора. '
                                'Закройте консоли узлов и нажмите «Подготовить лабу» снова.')
