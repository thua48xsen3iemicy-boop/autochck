"""Доп. проверки лабы OKFKS4-demo: веб-приложение на uvicorn под systemd.

На каждом узле из NODES проверяется:
  - пользователь APP_USER;
  - каталог APP_DIR с виртуальным окружением APP_DIR/VENV_NAME;
  - pip.conf прямо в venv (APP_DIR/VENV_NAME/pip.conf) с секцией [global],
    index-url и trusted-host — через `pip config --site list`, т.е. то, что
    pip в этом venv реально использует;
  - юнит SERVICE: User, Group, WorkingDirectory, ExecStart (uvicorn из venv,
    APP_MODULE, --host 0.0.0.0 --port APP_PORT), Restart=always;
  - SERVICE запущен (active/running), процесс от APP_USER;
  - SERVICE в автозагрузке (enabled);
  - GET http://127.0.0.1:APP_PORT/ROUTE (curl с самого узла) возвращает JSON
    {"command": "hostname", "ok": true, "result": <имя узла в лабе>},
    result — без учёта регистра.

Оценка только по этим пунктам и Hostnames (ONLY_EXTRA). Для похожей лабы с
другими параметрами — скопировать файл под именем лабы и поменять переменные.
На сервере лежит в /pnet/checks/OKFKS4-demo.py.
"""

import asyncio
import json
import shlex

ONLY_EXTRA = True

# ------------------------------------------------------------------ параметры
NODES = ['app1', 'app2', 'app3', 'app4']
APP_USER = 'apiuser'                 # от кого запускается сервис
APP_DIR = '/home/apiuser/app'        # каталог приложения и venv
VENV_NAME = 'env'                    # имя каталога venv внутри APP_DIR
APP_PORT = 8000
APP_MODULE = 'main:app'
SERVICE = 'app.service'
ROUTE = '/name'
PIP_INDEX_URL = 'http://10.19.36.2:3141/root/pypi/+simple/'
PIP_TRUSTED_HOST = '10.19.36.2'

# Баллы за пункт на каждом узле (max пункта = балл * число узлов)
POINTS = {
    'user': 1,
    'venv': 1,
    'pipconf': 1,
    'unit': 1,       # параметры юнита
    'running': 1,    # запущен от APP_USER
    'enabled': 1,    # в автозагрузке
    'route': 1,      # ответ ROUTE
}

LABELS = {
    'user': f'Пользователь {APP_USER}',
    'venv': f'Каталог {APP_DIR} и venv {VENV_NAME}',
    'pipconf': 'pip.conf в venv',
    'unit': f'Параметры {SERVICE}',
    'running': f'{SERVICE} запущен от {APP_USER}',
    'enabled': f'{SERVICE} в автозагрузке',
    'route': f'Ответ {ROUTE}',
}


def node_script():
    """Один shell-скрипт на узел: секции ==NAME, дальше их вывод."""
    q = shlex.quote
    venv = f'{APP_DIR}/{VENV_NAME}'
    return f"""
echo ==UID; id -u {q(APP_USER)} 2>/dev/null
echo ==VENV; test -d {q(APP_DIR)} && test -f {q(venv + '/pyvenv.cfg')} && test -x {q(venv + '/bin/python')} && echo OK
echo ==PIPCONF; test -f {q(venv + '/pip.conf')} && {q(venv + '/bin/pip')} config --site list 2>/dev/null
echo ==SHOW; systemctl show {q(SERVICE)} -p LoadState -p ActiveState -p SubState -p UnitFileState -p User -p Group -p WorkingDirectory -p Restart -p MainPID -p ExecStart 2>/dev/null
echo ==OWNER; pid=$(systemctl show {q(SERVICE)} -p MainPID 2>/dev/null | cut -d= -f2); [ "${{pid:-0}}" -gt 0 ] 2>/dev/null && ps -o uid= -p "$pid"
echo ==HTTP; curl -s -m 5 {q(f'http://127.0.0.1:{APP_PORT}{ROUTE}')}
echo; echo ==END
"""


def parse_sections(out):
    sections, cur = {}, None
    for line in out.split('\n'):
        if line.startswith('==') and line[2:].strip().isupper():
            cur = line[2:].strip()
            sections[cur] = []
        elif cur:
            sections[cur].append(line.rstrip('\r'))
    return sections


def parse_show(lines):
    props = {}
    for line in lines:
        if '=' in line:
            k, v = line.split('=', 1)
            props[k] = v
    return props


def exec_argv(exec_start):
    """'{ path=... ; argv[]=/x/uvicorn main:app --host ... ; ... }' -> [argv]."""
    if 'argv[]=' not in exec_start:
        return []
    return exec_start.split('argv[]=', 1)[1].split(' ;', 1)[0].split()


def cli_option(argv, name):
    """Значение --name X или --name=X из argv, иначе None."""
    for i, a in enumerate(argv):
        if a == name and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith(name + '='):
            return a.split('=', 1)[1]
    return None


def check_node(node, out):
    """-> ({пункт: True/False}, [ошибки]) для одного узла."""
    ok = dict.fromkeys(POINTS, False)
    errs = []
    if not out or out.startswith('NONE') or '==END' not in out:
        return ok, [f'{node}: узел не ответил на проверку']
    s = parse_sections(out)
    uid = ''.join(s.get('UID', [])).strip()

    ok['user'] = uid.isdigit()
    if not ok['user']:
        errs.append(f'{node}: нет пользователя {APP_USER}')

    ok['venv'] = 'OK' in s.get('VENV', [])
    if not ok['venv']:
        errs.append(f'{node}: нет каталога {APP_DIR} или виртуального окружения {APP_DIR}/{VENV_NAME}')

    pip = {}
    for line in s.get('PIPCONF', []):
        if '=' in line:
            k, v = line.split('=', 1)
            pip[k.strip()] = v.strip().strip('\'"')
    index_ok = pip.get('global.index-url', '').rstrip('/') == PIP_INDEX_URL.rstrip('/')
    trusted_ok = PIP_TRUSTED_HOST in pip.get('global.trusted-host', '').split()
    ok['pipconf'] = index_ok and trusted_ok
    if not ok['pipconf']:
        what = [n for n, good in (('index-url', index_ok), ('trusted-host', trusted_ok)) if not good]
        errs.append(f'{node}: в {APP_DIR}/{VENV_NAME}/pip.conf нет [global] или неверно: {", ".join(what)}')

    show = parse_show(s.get('SHOW', []))
    if show.get('LoadState') != 'loaded':
        errs.append(f'{node}: юнит {SERVICE} не найден')
    else:
        argv = exec_argv(show.get('ExecStart', ''))
        expected = {
            'User': show.get('User') == APP_USER,
            'Group': show.get('Group') == APP_USER,
            'WorkingDirectory': show.get('WorkingDirectory', '').lstrip('-!').rstrip('/') == APP_DIR.rstrip('/'),
            'ExecStart': (bool(argv) and argv[0] == f'{APP_DIR}/{VENV_NAME}/bin/uvicorn'
                          and APP_MODULE in argv[1:]
                          and cli_option(argv, '--host') == '0.0.0.0'
                          and cli_option(argv, '--port') == str(APP_PORT)),
            'Restart': show.get('Restart') == 'always',
        }
        bad = [k for k, good in expected.items() if not good]
        ok['unit'] = not bad
        if bad:
            errs.append(f'{node}: в {SERVICE} неверно: {", ".join(bad)}')

        owner = ''.join(s.get('OWNER', [])).strip()
        running = show.get('ActiveState') == 'active' and show.get('SubState') == 'running'
        ok['running'] = running and uid.isdigit() and owner == uid
        if not running:
            errs.append(f'{node}: {SERVICE} не запущен ({show.get("ActiveState")}/{show.get("SubState")})')
        elif not ok['running']:
            errs.append(f'{node}: процесс {SERVICE} запущен не от {APP_USER}')

        ok['enabled'] = show.get('UnitFileState') == 'enabled'
        if not ok['enabled']:
            errs.append(f'{node}: {SERVICE} не добавлен в автозагрузку ({show.get("UnitFileState")})')

    body = '\n'.join(s.get('HTTP', [])).strip()
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    ok['route'] = (isinstance(data, dict) and data.get('command') == 'hostname'
                   and data.get('ok') is True
                   and str(data.get('result', '')).lower() == node.lower())
    if not ok['route']:
        shown = body[:120] if body else 'нет ответа'
        errs.append(f'{node}: http://127.0.0.1:{APP_PORT}{ROUTE} вернул не то, что ожидалось: {shown}')

    return ok, errs


async def check(ctx):
    script = node_script()
    outs = await asyncio.gather(*(ctx.run(node, script) for node in NODES))
    totals = dict.fromkeys(POINTS, 0)
    for node, out in zip(NODES, outs):
        ok, errs = check_node(node, out)
        for key, good in ok.items():
            if good:
                totals[key] += POINTS[key]
        for e in errs:
            ctx.error(e)
    for key, points in POINTS.items():
        ctx.add_check(LABELS[key], totals[key], points * len(NODES))
