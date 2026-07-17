import pymysql
import logging
from fastapi import FastAPI, Form, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
# from fastapi.templating import Jinja2Templates
import subprocess
import uvicorn
import re, sys, os
import asyncio
import os.path
from collections import defaultdict
from collections import deque
import socket
import json
import sqlite3
import time
import telnetlib
import argparse
import base64
import chardet
import ipaddress
from collections import Counter
import traceback
from datetime import datetime
import pexpect

from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import httpx
import ssl
import csv
from typing import List
import aiofiles


lock = asyncio.Lock()

# Настройка логгирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
app.mount("/static", StaticFiles(directory="/pnet/report-stu/static"), name="static")
# Шаблоны версионируются в репозитории в templates/ и деплоятся сюда на appliance.
# results.html (дашборд студента) должен лежать в /pnet/report-stu/templates.
templates = Jinja2Templates(directory="/pnet/report-stu/templates")
no_run = False
force = False
admfile_path = '/pnet/admins.txt'
usrfile_path = '/data/username.txt'
ipfile_path = '/data/clientip'
if os.path.isfile(ipfile_path):
    with open(ipfile_path) as f:
        clientip = f.read().strip()
else:
    clientip = False
with open(usrfile_path) as f:
    username = f.read().strip()
with open(admfile_path) as file:
    admin_list = [line.rstrip() for line in file]
    print('admins', admin_list)

# ------------------------------------------------------------------ Результаты (SQLite)
# По одной БД на студента, в его личном mount-point (cephfs), по аналогии с result.json.
RESULT_DB_PATH = '/data/result.db'

def init_db(db_path=RESULT_DB_PATH):
    """Создаёт схему БД результатов (идемпотентно). Вызывается на старте."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                username TEXT,
                clientip TEXT,
                lab_path TEXT,
                status TEXT,
                score INTEGER,
                max_score INTEGER,
                percent REAL,
                grade INTEGER,
                lab_done INTEGER,
                errors_json TEXT,
                errorinfo TEXT,
                debug_json TEXT,
                penalties_json TEXT
            );
            CREATE TABLE IF NOT EXISTS check_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL REFERENCES runs(id),
                name TEXT,
                score INTEGER,
                max INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_runs_lab_ts ON runs(lab_path, ts);
            CREATE INDEX IF NOT EXISTS idx_items_run ON check_items(run_id);
        """)
        # Миграция для БД, созданных до появления penalties_json
        cols = [r[1] for r in conn.execute("PRAGMA table_info(runs)")]
        if 'penalties_json' not in cols:
            conn.execute("ALTER TABLE runs ADD COLUMN penalties_json TEXT")
        conn.commit()
    finally:
        conn.close()

def grade_from_percent(percent):
    """Процент выполнения -> оценка 2..5."""
    if percent >= 86:
        return 5
    elif percent >= 71:
        return 4
    elif percent >= 51:
        return 3
    return 2

# Множитель веса для критичных проверок (грубые ошибки сетевого администратора
# стоят дороже, но раздел всё равно не обнуляется от одной ошибки). Остальные — вес 1.
# Модель подсчёта: каждая проверка = набор элементов, max = число элементов,
# score = max - число ошибок (одна ошибка = -1 элемент), затем score/max умножаются на вес.
CHECK_WEIGHTS = {
    'IP is private': 3,
    'nodup_ipaddr': 3,
    'snat_nftables': 3,
    'Default gw good': 3,
}

# Штрафные проверки: то, чего быть НЕ должно (по умолчанию отсутствует), поэтому
# правильное состояние не даёт баллов (не входит в max), а нарушение вычитает
# указанное число баллов из итогового счёта. Значение — штраф за каждый узел-нарушитель.
PENALTIES = {
    'Forwarding_disable': 10,
    # Лишний VLAN на коммутаторе (создан, но заданию не соответствует) — мягко
    'vlan_extra': 1,
    # Лишний VLAN, фактически назначенный на порт узла из подсказки, —
    # это уже ошибка конфигурации
    'vlan_extra_used': 3,
    # Выключенный (shutdown) порт коммутатора, ведущий к узлу задания:
    # vlan может быть настроен верно, но узел отрезан от сети
    'vlan_port_shutdown': 3,
}

# Человекочитаемые названия проверок для отчёта вынесены в общий модуль
# check_labels.py (используется и reportsrv.py). Fallback — пустой словарь,
# если файл не задеплоен рядом: тогда показываются сырые ключи.
try:
    from check_labels import CHECK_LABELS
except ImportError:
    CHECK_LABELS = {}

# Диагностические словари, собранные при проверке, — их сохраняем в debug_json,
# чтобы сервер отчётов мог показать «собранную информацию» по попытке. Снимок
# делается ДО pop() (см. финальный return), иначе часть словарей уже удалена.
# Ключи, которых нет в конкретном прогоне, просто пропускаются.
COLLECTED_KEYS = [
    'bridges',
    'dict_of_vmname_and_uid',
    'dict_of_intname_and_mac',
    'dict_of_name_fullcmd',
    'dict_of_vmnames_hostname',
    'mikrotik_raw_output',
    'dict_of_name_routeros_script',
    'l2_vlans_debug',
    'l2_domains',
    'l2_subints',
    'dict_of_vmnames_defgw',
    'dict_of_vmnames_dnssrv',
    'dict_of_intnames_ipaddr',
    'dict_of_intnames_ipaddr_for_answer',
    'dict_of_intnames_network',
    'list_of_routers',
    'dict_of_bridges_vmnames',
    'dict_of_routers_address',
    'list_of_networks',
    'dict_of_name_winservers_script',
]

def save_run(run, checks, db_path=RESULT_DB_PATH):
    """Сохраняет один прогон (runs) и разбивку по проверкам (check_items). Возвращает run_id.

    Блокирующая функция — в async-хендлере вызывать через run_in_executor.
    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO runs
               (ts, username, clientip, lab_path, status, score, max_score,
                percent, grade, lab_done, errors_json, errorinfo, debug_json, penalties_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run['ts'], run['username'], run['clientip'], run['lab_path'],
             run['status'], run['score'], run['max_score'], run['percent'],
             run['grade'], run['lab_done'], run['errors_json'],
             run.get('errorinfo'), run.get('debug_json'), run.get('penalties_json')))
        run_id = cur.lastrowid
        cur.executemany(
            "INSERT INTO check_items (run_id, name, score, max) VALUES (?,?,?,?)",
            [(run_id, name, c['score'], c['max']) for name, c in checks.items()])
        conn.commit()
        # Вливаем WAL в основной файл БД: сервер отчётов читает эту БД по сети
        # через immutable=1 (нет прав писать -shm в чужом каталоге) и видит только
        # закоммиченное в основной файл. Без чекпоинта свежие прогоны застряли бы в -wal.
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.OperationalError as e:
            log('wal_checkpoint err', e)
        return run_id
    finally:
        conn.close()

def load_dashboard(db_path=RESULT_DB_PATH):
    """Читает историю прогонов для дашборда: список лаб, внутри — попытки (новые первыми).

    Возвращает [{"lab_path", "attempts": [...], "latest": {...}}], где каждая
    попытка содержит поля runs + распарсенные errors и разбивку items.
    Блокирующая функция — вызывать через run_in_executor.
    """
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        runs = [dict(r) for r in conn.execute(
            "SELECT * FROM runs ORDER BY lab_path, id DESC")]
        items_by_run = {}
        for it in conn.execute("SELECT run_id, name, score, max FROM check_items ORDER BY id"):
            items_by_run.setdefault(it['run_id'], []).append(
                {'name': it['name'], 'score': it['score'], 'max': it['max']})
    finally:
        conn.close()

    labs = {}
    for r in runs:
        r['items'] = items_by_run.get(r['id'], [])
        try:
            r['errors'] = json.loads(r['errors_json']) if r['errors_json'] else []
        except (ValueError, TypeError):
            r['errors'] = []
        try:
            r['penalties'] = json.loads(r.get('penalties_json')) if r.get('penalties_json') else {}
        except (ValueError, TypeError):
            r['penalties'] = {}
        labs.setdefault(r['lab_path'], []).append(r)

    result = []
    for lp, att in labs.items():
        # Короткое имя лабы из пути: //GROUPS/OA-2501/KS24.unl -> KS24
        base = lp.rsplit('/', 1)[-1]
        name = base.rsplit('.', 1)[0] if '.' in base else base
        result.append({'lab_path': lp, 'name': name, 'attempts': att, 'latest': att[0]})
    # Лабы с самой свежей попыткой — вверх
    result.sort(key=lambda l: l['latest']['id'], reverse=True)
    return result

def cidr_to_network_mask(cidr: str) -> str:
    """
    Принимает строку вида "10.1.2.2/30" и возвращает 
    "10.1.2.0 255.255.255.252". 
    Если формат неверен или отсутствует префикс, выдаёт ValueError.
    """
    try:
        iface = ipaddress.ip_interface(cidr)
    except ValueError:
        # raise ValueError(f"Неверный формат, ожидался IP/префикс: {cidr}")
        return "99.99.9.9 255.255.255.255"
    network = iface.network
    return f"{network.network_address} {network.netmask}"

def parse_ovs_output(output: str):
    """
    Парсит вывод ovs-vsctl show и проверяет:
      - наличие любого Bridge
      - что интерфейс ens3 подключён к порту БЕЗ тега
      - что интерфейс ens4 подключён к порту с tag 15
      - что интерфейс ens5 подключён к порту с tag 25
      - что есть порт с tag 99 и type internal (возвращаем его имя интерфейса)

    Возвращает словарь с ключами:
      - 'bridge': True, если найден хотя бы один Bridge, иначе None
      - 'ens3':  True, если найден Interface "ens3" под портом без tag, иначе None
      - 'ens4':  True, если найден Interface "ens4" под портом с tag 15, иначе None
      - 'ens5':  True, если найден Interface "ens5" под портом с tag 25, иначе None
      - 'mgmt':  имя интерфейса (например, "mgmt-int"), если найдён порт с tag 99 и type internal, иначе None
    """
    result = {
        'bridge': None,
        'ens3': None,
        'ens4': None,
        'ens5': None,
        'mgmt': None
    }

    current_port = None
    current_tag = None
    current_interface = None
    current_interface_tag = None

    for line in output.splitlines():
        stripped = line.strip()

        # 1) Любая строка "Bridge <имя>" говорит, что мост есть
        if stripped.startswith("Bridge "):
            result['bridge'] = True

        # 2) Как только видим "Port <имя_порта>", переходим в контекст нового порта
        if stripped.startswith("Port "):
            parts = stripped.split()
            if len(parts) >= 2:
                current_port = parts[1]
                current_tag = None
                current_interface = None
                current_interface_tag = None

        # 3) Если есть строка "tag: <число>", сохраняем её как tag текущего порта
        if stripped.startswith("tag:"):
            parts = stripped.split()
            if len(parts) >= 2:
                try:
                    current_tag = int(parts[1])
                except ValueError:
                    current_tag = None

        # 4) Когда встречаем "Interface <имя_интерфейса>", запоминаем его и ассоциируем с текущим tag
        if stripped.startswith("Interface "):
            parts = stripped.split()
            if len(parts) >= 2:
                iface_name = parts[1]
                current_interface = iface_name
                current_interface_tag = current_tag

                # Проверяем сразу ens3/ens4/ens5 по условию (только по тегу)
                if iface_name == 'ens3' and current_interface_tag is None:
                    result['ens3'] = True
                elif iface_name == 'ens4' and current_interface_tag == 15:
                    result['ens4'] = True
                elif iface_name == 'ens5' and current_interface_tag == 25:
                    result['ens5'] = True

        # 5) Когда видим "type: <тип>", проверяем, не относится ли он к порту с tag 999
        if stripped.startswith("type:"):
            parts = stripped.split()
            if len(parts) >= 2:
                type_val = parts[1]
                # Если тип = internal и тег текущего интерфейса = 999 → запомним имя интерфейса
                if type_val == 'internal' and current_interface_tag == 99:
                    if result['mgmt'] is None:
                        result['mgmt'] = current_interface

    return result

def get_network_from_address(cidr: str) -> str:
    """
    Принимает строку вида "10.1.2.2/30" и возвращает сеть "10.1.2.0/30",
    в которой находится указанный адрес. Если формат неверен — ValueError.
    """
    try:
        iface = ipaddress.ip_interface(cidr)
    except ValueError:
        # raise ValueError(f"Неверный формат IP/префикса: {cidr}")
        return "99.99.9.9/32"
    network = iface.network
    return str(network)


def log_and_print(message: str):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"{current_time} - {message}"
    # Логгирование в файл
    with open("/data/webapp.log", "a") as log_file:
        log_file.write(log_entry + "\n")
    # Вывод на экран
    print(log_entry)

def check_masquerade(ruleset_lines, iface):
    """
    Принимает список строк — вывод команды `nft list ruleset`
    и имя интерфейса iface (например, "ens3").
    Возвращает True, если найдена строка с `oifname "<iface>" masquerade`, иначе False.
    """
    target = f'oifname "{iface}"'
    for line in ruleset_lines:
        if target in line and "masquerade" in line:
            return True
    return False

def check_nftables_status(status_lines):
    """
    Принимает список строк — вывод `systemctl status nftables.service`.
    Возвращает True, если:
      1) в строке Active есть подстрока "active (exited)" (служба запущена как oneshot), и
      2) в строке Loaded есть "; enabled;" (включена в автозагрузку).
    Иначе возвращает False.
    """
    is_active_exited = False
    is_enabled = False

    for line in status_lines:
        stripped = line.strip()

        # Проверяем, что служба запущена как oneshot ("active (exited)")
        if stripped.startswith("Active:"):
            if "active (exited)" in stripped:
                is_active_exited = True

        # Проверяем, что в строке Loaded есть "; enabled;"
        if stripped.startswith("Loaded:"):
            if "; enabled;" in stripped:
                is_enabled = True

    return is_active_exited and is_enabled

def is_ip_in_network(ip_with_prefix: str, network: str) -> bool:
    """
    Принимает IP-адрес с префиксом (например, "192.168.1.5/24") и адрес сети в формате CIDR 
    (например, "192.168.1.0/24"). Возвращает True, если хостовая часть IP-адреса находится в указанной сети.

    :param ip_with_prefix: строка вида "IP/префикс", например "10.0.0.5/24"
    :param network: сеть в формате CIDR, например "10.0.0.0/24"
    :return: True, если IP (без учёта его префикса) принадлежит сети; иначе False.
    :raises ValueError: если один из аргументов имеет неверный формат.
    """
    try:
        iface = ipaddress.ip_interface(ip_with_prefix)
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        raise ValueError(f"Неверный формат: {e}")

    return iface.ip in net

def parse_ip_addr_show(lines):
    """
    Принимает список строк из вывода `ip addr show` и возвращает словарь:
    {<имя интерфейса>: <IPv4-адрес с префиксом>}.
    Если у интерфейса нет IPv4-адреса, в качестве значения записывается None.

    :param lines: список строк (каждая строка — элемент списка), полученных из `ip addr show`
    :return: dict, где ключ — имя интерфейса, значение — IPv4-адрес/префикс или None
    """
    iface_to_addr = {}
    current_iface = None

    # Регулярное выражение для строки с заголовком интерфейса: "1: lo: <...>"
    header_re = re.compile(r'^\d+:\s+([^:]+):')

    # Регулярка для строки с IPv4-адресом: "    inet 192.168.1.2/24 brd ... scope ..."
    inet_re = re.compile(r'\s+inet\s+([\d\.]+/\d+)')

    for line in lines:
        line = line.rstrip()

        # Если встретили строку-заголовок интерфейса
        m_header = header_re.match(line)
        if m_header:
            current_iface = m_header.group(1)
            iface_to_addr[current_iface] = None
            continue

        # Если внутри блока интерфейса ищем первую строку с "inet " (IPv4)
        if current_iface is not None:
            m_inet = inet_re.match(line)
            if m_inet:
                # Сохраняем адрес (с префиксом) и больше не ищем IPv4 для этого интерфейса
                iface_to_addr[current_iface] = m_inet.group(1)
                # Можно сбросить current_iface, но тогда не сможем связывать следующие ether/inet6…
                # Оставляем current_iface, но при повторном inet не перезаписываем
                # Поэтому проверяем, чтобы не перезаписывать уже найденное:
                continue

    return iface_to_addr

def check_network_size(entry: str, count: int, mode: str) -> bool:
    """
    Проверяет размер сети на основе переданного IP-адреса или сети в формате CIDR.

    :param entry: строка с IP-адресом **с префиксом** (например, "192.168.1.10/24") 
                  или сетью в формате CIDR (например, "192.168.1.0/24").
    :param count: число адресов для сравнения.
    :param mode:  "more" или "less". 
                  - "more": вернуть True, если сеть (в которой находится адрес или сама сеть) 
                    может вместить **строго больше** адресов, чем count.
                  - "less": вернуть True, если сеть **не превышает** по количеству адресов count.
    :return: булево значение в зависимости от режима сравнения.
    :raises ValueError: если mode не равен "more" или "less", или entry задан неверно.
    """

    # Преобразуем entry (IP/префикс или сеть/префикс) в объект ip_network.
    # strict=False позволяет передавать IP-адрес с префиксом, чтобы получить сеть, в которой он находится.
    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError as e:
        raise ValueError(f"Неверный формат entry: {entry}") from e

    total_addresses = network.num_addresses

    if mode == "more":
        return total_addresses > count
    elif mode == "less":
        return total_addresses <= count
    else:
        raise ValueError(f"Неверный режим '{mode}'. Ожидается 'more' или 'less'.")

def same_network_different(addr1: str, addr2: str) -> bool:
    """
    Принимает две строки с IP-адресами+префиксом (например, "192.168.1.5/24" и "192.168.1.10/24").
    Возвращает True, если:
      1) Адреса (включая хост-часть) не одинаковые, и
      2) Оба адреса принадлежат одной и той же сети (по указанному префиксу).
    В противном случае возвращает False.
    
    :param addr1: IP-адрес с префиксом (CIDR), например "10.0.0.1/24"
    :param addr2: IP-адрес с префиксом (CIDR), например "10.0.0.5/24"
    :return: True, если адреса различны и лежат в одной сети; иначе False.
    :raises ValueError: если один из входных аргументов имеет неверный формат.
    """
    try:
        iface1 = ipaddress.ip_interface(addr1)
        iface2 = ipaddress.ip_interface(addr2)
    except ValueError as e:
        raise ValueError(f"Неверный формат адреса: {e}")

    # Хостовые адреса
    ip1 = iface1.ip
    ip2 = iface2.ip

    # Сети, полученные из интерфейсов
    net1 = iface1.network
    net2 = iface2.network

    # Проверяем, что IP-адреса не одинаковые и сети совпадают
    return (ip1 != ip2) and (net1 == net2)


def prestart():
    db_config = {
        'host': 'localhost',
        'user': 'pnetlab',
        'password': 'pnetlab',
        'database': 'pnetlab_db'
    }
    log_and_print('Prestart func')
    try:
        init_db()
    except Exception as e:
        log('init_db err', e)
    was_run = os.path.isfile('/tmp/prestart_run')

    if not was_run or force:
        subprocess.Popen(['/pnet/remote.py', '&'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(['/pnet/swapmon.py', '&'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # subprocess.Popen(['/bin/systemctl', 'restart', 'mysql', 'apache2'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        open('/tmp/prestart_run', 'a').close()
    return 0

def log(message: str, msg2: str):
    message = message + " " + str(msg2)
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"{current_time} - {message}"
    # Логгирование в файл
    with open("/data/webapp.log", "a") as log_file:
        log_file.write(log_entry + "\n")
    # Вывод на экран
    #print(log_entry)

def get_vmname_by_intname(intname, dict_of_name_and_intname):
    for vmname in dict_of_name_and_intname:
        for intname2 in dict_of_name_and_intname[vmname]:
            if intname == intname2:
                return vmname
    return False

def mask_to_prefix(mask):
    binary_str = ''
    for octet in mask.split('.'):
        binary_str += bin(int(octet))[2:].zfill(8)
    return binary_str.count('1')

def get_network_address(ip_with_prefix):
    network = ipaddress.ip_network(ip_with_prefix, strict=False)
    return f"{network.network_address}/{network.prefixlen}"

def is_private_network(ip_with_prefix):
    network = ipaddress.ip_network(ip_with_prefix, strict=False)
    return network.is_private

def check_duplicates(dictionary_orig):
    dictionary = {k: v for k, v in dictionary_orig.items() if v is not 'NONE' and v is not 'DOWN'}
    values_count = Counter(dictionary.values())
    duplicate_values = {value for value, count in values_count.items() if count > 1}
    duplicate_keys = [key for key, value in dictionary.items() if value in duplicate_values]
    # print('dup', duplicate_keys)
    return duplicate_keys

def check_same_network(addresses_with_prefix):
    #print('addresses_with_prefix:', addresses_with_prefix)
    networks = [ipaddress.ip_network(addr, strict=False) for addr in addresses_with_prefix]
    #print('networks', networks)
    first_network = networks[0]
    for network in networks[1:]:
        #if not first_network.overlaps(network):
        if first_network != network:
            return False    
    return True

def check_network_overlap(networks_with_prefix):
    network_objects = [ipaddress.ip_network(net, strict=False) for net in networks_with_prefix]
    
    for i, net1 in enumerate(network_objects):
        for j, net2 in enumerate(network_objects[i+1:], i+1):
            if net1.overlaps(net2):
                return True
    return False


def fetch_single_lab_session():
    # Параметры для подключения к базе данных
    db_config = {
        'host': 'localhost',
        'user': 'pnetlab',
        'password': 'pnetlab',
        'database': 'pnetlab_db'
    }
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            #sql_query = "SELECT lab_session_lid,lab_session_path FROM lab_sessions WHERE lab_session_pod=44 AND lab_session_joined=44"
            sql_query = "SELECT lab_session_lid, lab_session_path FROM lab_sessions WHERE lab_session_pod IN (43, 44) AND lab_session_joined = lab_session_pod"
            cursor.execute(sql_query)
            results = cursor.fetchall()

            if len(results) == 1:
                log('lab path:', results[0])
                return results[0] 
            elif len(results) == 0:
                return("no")
            else:
                
                sql_query = 'UPDATE lab_sessions SET lab_session_joined = "" WHERE lab_session_joined=44'
                cursor.execute(sql_query)
                connection.commit()
                log('multilab:', results)
                return("moreone")
    finally:
        connection.close()

def find_uuid_in_file_and_ps(file_path):
    uuids = []  # Использование множества для хранения уникальных UUID
    type_of_vm = []
    name_of_vm = []
    image_of_vm = []
    vmname_uids = []
    dict_of_vmname_and_uid = {}
    u = ''
    n = ''
    # Чтение файла и поиск UUID
    with open(file_path, 'r') as file:
        for line in file:
            if 'node' in line:
                # u/n сбрасываются на каждой ноде: раньше нода без uuid
                # (IOL) наследовала uuid предыдущей в dict_of_vmname_and_uid
                u = ''
                n = ''
                # IOL-ноды не qemu: их uuid (если вдруг есть) не должен
                # участвовать в сверке количества с процессами qemu
                is_iol = 'template="iol"' in line
                match = re.search(r'\suuid="([a-fA-F0-9\-]+)"\s', line)
                if match and not is_iol:
                    u = match.group(1)
                    uuids.append(match.group(1))

                match = re.search(r'\stemplate="([\w\-]+)"\s', line)
                if match:
                    type_of_vm.append(match.group(1))

                match = re.search(r'\sname="([\w\-]+)"\s', line)
                if match:
                    n = match.group(1)
                    name_of_vm.append(match.group(1))

                match = re.search(r'\simage="([\w\-]+)"\s', line)
                if match:
                    image_of_vm.append(match.group(1))
                if u and n:
                    dict_of_vmname_and_uid[n] = u
    # Запуск команды 'pgrep -af qemu'
    process_output = subprocess.Popen(['pgrep', '-af', 'qemu-system-x86_64'], stdout=subprocess.PIPE)
    output = process_output.communicate()[0].decode().splitlines()
    #print(image_of_vm)
    # Проверка условий
    dict_of_name_and_ostype = []
    if len(uuids) == len(output):
        all_uuids_present = all(uuid in ' '.join(output) for uuid in uuids)
        print(all_uuids_present)

        if all_uuids_present:
            #print("Количество UUID совпадает с числом процессов qemu, и каждый UUID присутствует в выводе pgrep.")
            #print(type_of_vm, name_of_vm)
            dict_of_name_and_ostype = dict(zip(name_of_vm, type_of_vm))
            return (dict_of_name_and_ostype, dict_of_vmname_and_uid)
            #print(dict_of_name_and_ostype)

        else:
            return("multilab", output)
    else:
        log('Лишние ноды', output)
        return("count", output)

def parse_unl_nodes(lab_file):
    """Разбирает ноды из файла лабы (.unl):
    {имя: {'id': int|None, 'template': str, 'image': str,
           'iface_names': {номер инта: 'e0/0', ...}}}.

    iface_names берутся из дочерних <interface> элементов ноды — для IOL
    там лежат фактические имена портов (e0/0, e0/1, ...), которые нужны,
    чтобы сопоставить tap-интерфейсы с выводом show-команд коммутатора.
    """
    try:
        with open(lab_file, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError as e:
        log('parse_unl_nodes read err', e)
        return {}
    nodes = {}
    for m in re.finditer(r'<node\b([^>]*?)(?:/>|>(.*?)</node>)', content, re.DOTALL):
        attrs, body = m.group(1), m.group(2) or ''
        name_m = re.search(r'\sname="([^"]+)"', attrs)
        if not name_m:
            continue
        id_m = re.search(r'\sid="(\d+)"', attrs)
        tpl_m = re.search(r'\stemplate="([^"]+)"', attrs)
        img_m = re.search(r'\simage="([^"]+)"', attrs)
        ifaces = {}
        for im in re.finditer(r'<interface\b([^>]*?)/?>', body):
            iattrs = im.group(1)
            iid = re.search(r'\sid="(\d+)"', iattrs)
            iname = re.search(r'\sname="([^"]+)"', iattrs)
            if iid and iname:
                ifaces[int(iid.group(1))] = iname.group(1)
        nodes[name_m.group(1)] = {
            'id': int(id_m.group(1)) if id_m else None,
            'template': tpl_m.group(1) if tpl_m else '',
            'image': img_m.group(1) if img_m else '',
            'iface_names': ifaces,
        }
    return nodes

def get_iol_console_ports():
    """Консольные порты запущенных IOL-нод: {имя ноды: tcp-порт}.

    У IOL нет qemu-процесса с monitor.sock, поэтому порт определяем по
    самому процессу iol_wrapper: имя ноды — его аргумент -t, порт консоли —
    слушающий TCP-порт этого процесса (ss -tlnp). Если ss недоступен или
    порт не нашёлся, используем формулу EVE-NG: 32768 + 128*(-T) + (-D).
    """
    try:
        psout = subprocess.check_output(['ps', 'aux'], universal_newlines=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        log('get_iol_console_ports ps err', e)
        return {}
    listen_by_pid = {}
    try:
        ssout = subprocess.check_output(['ss', '-tlnp'], universal_newlines=True)
        for line in ssout.splitlines():
            pm = re.search(r':(\d+)\s', line)
            if not pm:
                continue
            for pidm in re.finditer(r'pid=(\d+)', line):
                listen_by_pid.setdefault(int(pidm.group(1)), set()).add(int(pm.group(1)))
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        log('get_iol_console_ports ss err', e)
    ports = {}
    for line in psout.splitlines():
        if 'iol_wrapper' not in line or 'grep' in line:
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            continue
        pid = int(parts[1])
        nm = re.search(r'-t\s+(\S+)', line)
        if not nm:
            continue
        name = nm.group(1).strip('"\'')
        lports = listen_by_pid.get(pid)
        if lports:
            ports[name] = min(lports)
        else:
            tm = re.search(r'-T\s+(\d+)', line)
            dm = re.search(r'-D\s+(\d+)', line)
            if tm and dm:
                ports[name] = 32768 + 128 * int(tm.group(1)) + int(dm.group(1))
    log('iol console ports', ports)
    return ports

def parse_brctl_show():
    try:
        # Выполнение команды brctl show и получение вывода
        output = subprocess.check_output(["brctl", "show"]).decode('utf-8')
    except FileNotFoundError:
        print("Команда brctl не найдена")
        return
    except subprocess.CalledProcessError as e:
        print(f"Ошибка выполнения команды brctl: {e}")
        return

    # Инициализация переменных и словаря для хранения информации
    bridge_data = defaultdict(list)
    current_bridge = ''

    # Парсинг вывода команды
    for line in output.split("\n")[1:]:  # Пропуск заголовочной строки
        if not line:
            continue
        columns = re.split(r'\s+', line.strip())

        # Если строка содержит имя моста
        if len(columns) >= 4:
            current_bridge = columns[0]
            bridge_data[current_bridge].append(columns[3])

        # Если строка содержит только имя интерфейса (подчинённого мосту)
        elif len(columns) == 1:
            bridge_data[current_bridge].append(columns[0])

    return dict(bridge_data)

def get_name_and_path_by_int_id(filter_str):
    try:
        # Выполнение команды и получение вывода
        output = subprocess.check_output(["ps", "aux"], universal_newlines=True)
    except FileNotFoundError:
        return "Команда ps aux не найдена"
    except subprocess.CalledProcessError as e:
        return f"Ошибка выполнения команды ps aux: {e}"

    # Фильтрация вывода для поиска строки с qemu и заданным фильтром
    filtered_line = next((line for line in output.split('\n') if "qemu" in line and filter_str in line), None)
    log('filtered line', filtered_line)
    if not filtered_line:
        return f"Строка с qemu и {filter_str} не найдена"

    # Поиск имени виртуальной машины
    name_match = re.search(r'-name (\S+)', filtered_line)
    vm_name = name_match.group(1) if name_match else "Не найдено"

    # Поиск идентификаторов сетевых карт
    #net_ids = re.findall(r'-netdev tap,id=(\w+),', filtered_line)

    # Поиск значения -path
    path_match = re.search(r'id=monitor,path=/opt/unetlab/tmp/(\S+)', filtered_line)
    path_value = path_match.group(1) if path_match else print("Не найдено")
    log('vmanme and path_value', str(vm_name) + ' ' + str(path_value))
    return vm_name, path_value.replace('monitor.sock,server,nowait','')

def get_tap_mac_map():
    """Строит соответствие {ifname_tap: mac} по командным строкам всех qemu-процессов.

    Источник — единственный вызов `ps aux`. Пары берём по общему netdev id,
    связывая `-device ...,netdev=netN,mac=MAC` с `-netdev tap,id=netN,ifname=IFNAME`.
    MAC приводим к нижнему регистру для сравнения с выводом `ip a` (link/ether).
    Осиротевшие tap'ы (без процесса qemu) сюда естественно не попадают.
    """
    try:
        output = subprocess.check_output(["ps", "aux"], universal_newlines=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        log('get_tap_mac_map err', e)
        return {}

    tap_mac = {}
    for line in output.splitlines():
        if 'qemu' not in line:
            continue
        # netdev id -> mac (из -device ...,netdev=netN,mac=...)
        netid_to_mac = dict(re.findall(r'netdev=(\w+),mac=([0-9a-fA-F:]{17})', line))
        # netdev id -> ifname (из -netdev tap,id=netN,ifname=...)
        for netid, ifname in re.findall(r'id=(\w+),ifname=([^,]+)', line):
            if netid in netid_to_mac:
                tap_mac[ifname] = netid_to_mac[netid].lower()
    return tap_mac

def start_bridge(unl_nodes=None):

    unl_nodes = unl_nodes or {}
    bridges = parse_brctl_show()
    log('bridges:', bridges)
    #print('bridges', bridges)
    list_of_vmid = []
    list_of_intname= []
    dict_of_name_and_intname = {}
    dict_of_name_and_path = {}
    list_of_vmnames = []

    orphan_ports = []
    cleaned_by_bridge = {}
    # id ноды -> имя для IOL-нод лабы (у них нет процесса qemu, разбираем отдельно)
    iol_ids = {d['id']: n for n, d in unl_nodes.items()
               if d.get('template') == 'iol' and d.get('id') is not None}
    pending_iol = []      # (мост, порт) — vunl-порты без qemu, кандидаты в IOL
    resolved_pairs = []   # (имя qemu-ноды, порт) — для обучения привязки IOL

    def register_port(vmname, port):
        list_of_intname.append(port)
        list_of_vmid.append(port.split('_')[0])
        list_of_vmnames.append(vmname)
        if vmname in dict_of_name_and_intname:
            dict_of_name_and_intname[vmname] = dict_of_name_and_intname[vmname] + ' ' + port
        else:
            dict_of_name_and_intname[vmname] = port

    for bridge in bridges:
        cleaned_ports = []
        for port in bridges[bridge]:
            # Физический аплинк (eth0 под pnet0) и прочие не-vunl порты оставляем как есть
            if not port.startswith('vunl'):
                cleaned_ports.append(port)
                continue

            vmid = port.split('_')
            result = get_name_and_path_by_int_id(vmid[0])
            # get_name_and_path_by_int_id возвращает кортеж (vmname, vmpath) при успехе
            # и строку-ошибку, если живого qemu-процесса для этого tap нет.
            if not isinstance(result, tuple):
                if iol_ids:
                    # В лабе есть IOL-ноды — tap может принадлежать одной из них
                    pending_iol.append((bridge, port))
                else:
                    # У tap-интерфейса нет процесса qemu — осиротевший мост чужой/остановленной лабы
                    orphan_ports.append(port)
                continue

            vmname, vmpath, *_ = result
            cleaned_ports.append(port)
            register_port(vmname, port)
            resolved_pairs.append((vmname, port))

            dict_of_name_and_path[vmname] = vmpath

        cleaned_by_bridge[bridge] = cleaned_ports

    if pending_iol:
        # Привязываем vunl-порты без qemu-процесса к IOL-нодам. Их tap'ы
        # создаёт iol_wrapper, и имени tap'а в командной строке нет, поэтому
        # используем числовой префикс tap'а (vunl443_2 -> 443): он связан с id
        # ноды лабы постоянным смещением (base + id). Базу учим по уже
        # разобранным qemu-нодам той же лабы, а если qemu-нод нет — подбираем
        # такую, при которой каждый кандидат ложится на id какой-нибудь IOL-ноды.
        def tapnum(port):
            m = re.match(r'vunl(\d+)_', port)
            return int(m.group(1)) if m else None

        base_votes = Counter()
        for vmname, port in resolved_pairs:
            nid = unl_nodes.get(vmname, {}).get('id')
            num = tapnum(port)
            if nid is not None and num is not None:
                base_votes[num - nid] += 1

        cand_nums = {tapnum(p) for _b, p in pending_iol}
        cand_nums.discard(None)
        chosen_base = None
        if base_votes:
            chosen_base = base_votes.most_common(1)[0][0]
        elif cand_nums:
            fits = [b for b in sorted({num - nid for num in cand_nums for nid in iol_ids})
                    if all((num - b) in iol_ids for num in cand_nums)]
            if len(fits) == 1:
                chosen_base = fits[0]
        log('iol tap resolve', f'base_votes={dict(base_votes)} chosen={chosen_base} candidates={sorted(cand_nums)} iol_ids={iol_ids}')

        iol_console_ports = get_iol_console_ports()
        unresolved = []
        for bridge, port in pending_iol:
            num = tapnum(port)
            vmname = None
            if num is not None and chosen_base is not None and (num - chosen_base) in iol_ids:
                vmname = iol_ids[num - chosen_base]
            elif len(iol_ids) == 1 and len(cand_nums) == 1:
                # Единственная IOL-нода и один общий префикс tap'ов — её порты
                vmname = next(iter(iol_ids.values()))
            if vmname is None:
                unresolved.append(port)
                continue
            cleaned_by_bridge[bridge].append(port)
            register_port(vmname, port)
            if vmname not in dict_of_name_and_path and vmname in iol_console_ports:
                # Маркер iol:<port> — телнет-порт консоли, а не путь к сокету
                dict_of_name_and_path[vmname] = f'iol:{iol_console_ports[vmname]}'
        if unresolved:
            log('iol taps unresolved (treated as orphan)', unresolved)
            orphan_ports.extend(unresolved)

    # Мост оставляем, только если в нём остались валидные порты.
    # pnet0 при этом сохраняется автоматически — у него легитимно только eth0.
    cleaned_bridges = {b: p for b, p in cleaned_by_bridge.items() if p}

    removed_bridges = [b for b in bridges if b not in cleaned_bridges]
    if orphan_ports:
        log('orphan ports skipped (no qemu process)', orphan_ports)
        log('orphan bridges removed', removed_bridges)
        log_and_print(f'Пропущены осиротевшие интерфейсы без процесса qemu: {orphan_ports}, удалены мосты: {removed_bridges}')

    list_of_vmid = list(set(list_of_vmid))
    list_of_vmnames = list(set(list_of_vmnames))

        
 
    for vmname in list_of_vmnames:
        dict_of_name_and_intname[vmname] = dict_of_name_and_intname[vmname].split(" ")
    log('dict_of_name_and_path:', dict_of_name_and_path)
    log('list_of_vmnames:', list_of_vmnames)
    log('list_of_intname:', list_of_intname)
    log('dict_of_name_and_intname:', dict_of_name_and_intname)
   
    return(dict_of_name_and_path, list_of_vmnames, list_of_intname, dict_of_name_and_intname, cleaned_bridges)


def qga_recv_json(sock):
    """Читает из сокета qemu-guest-agent один полный JSON-ответ.

    Ответы QGA разделяются переводом строки. Одиночный recv не гарантирует
    целого ответа: большой вывод (ip -d a, крупные конфиги) приходит
    несколькими сегментами, и json.loads от куска ронял всю проверку.
    """
    buf = b''
    while b'\n' not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise socket.timeout('qga socket closed')
        buf += chunk
    line = buf.split(b'\n', 1)[0].strip()
    return json.loads(line.decode('utf-8'))

def execute_command_sync(command, os_type, socket_path):

    # Путь к сокету QEMU Monitor
    socket_path = f"/data/tmp/{socket_path}qga.sock"

    # Определение пути к оболочке в зависимости от типа ОС
    if os_type == "linux":
        shell_path = "/bin/sh"
        shell_args = ["-c"]
    elif os_type == "windows":
        shell_path = "cmd.exe"
        shell_args = ["/c"]
    else:
        shell_path = "PowerShell"
        shell_args = ["-Command"]

    # Команда для запуска
    exec_command = {
        "execute": "guest-exec",
        "arguments": {
            "path": shell_path,
            "arg": shell_args + [command],
            "capture-output": True
        }
    }

    # Подключение к сокету
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(15)
    #log('try connect to socket:', socket_path)
    sock.connect(socket_path)
    
    try:

        # Отправка команды для запуска
        sock.sendall(json.dumps(exec_command).encode("utf-8"))
        time.sleep(0.1)
        # Получение ответа с идентификатором процесса
        response = qga_recv_json(sock)
        process_id = response.get("return", {}).get("pid")

        # Если есть идентификатор процесса, запросить статус
        if process_id:
            status_command = {
                "execute": "guest-exec-status",
                "arguments": {
                    "pid": process_id
                }
            }

            # Засечь начальное время
            start_time = time.time()
            max_wait_time = 60  # Максимальное время ожидания в секундах
            
            while True:
                
                # Отправка команды для получения статуса
                sock.sendall(json.dumps(status_command).encode("utf-8"))
                time.sleep(0.1)
                # Получение ответа с результатом выполнения команды
                response = qga_recv_json(sock)
                log(f'_{socket_path} {command}', str(response)[:1500])
                # Если команда завершилась, вывести результат
                if response.get("return", {}).get("exited", False):
                    if response.get("return", {}).get("out-truncated"):
                        log('qga out-truncated', socket_path)
                    output = response.get("return", {}).get("out-data", "")
                    decoded_output = base64.b64decode(output).decode("utf-8")
                    #print(decoded_output.strip())

                    break
                
                # Проверка таймаута
                if time.time() - start_time > max_wait_time:
                    log("timeout:", "Timed out waiting for command to complete")
                    break
                
                # Ожидание перед следующим опросом статуса
                time.sleep(0.4)

        # Закрытие соединения
        #sock.close()
        return decoded_output.strip()

    except socket.timeout:
        log('socket read timeout error', socket_path)
        return 'err'
    finally:
        sock.close()




async def execute_command(cmd, ostype, socket_path, name, command_type):
    #async with lock:
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, execute_command_sync, cmd, ostype, socket_path)
    #print(result)
    if not result:
        result = 'NONE'
    if result == 'err':
        result = "NONEERR"
    #print('return', name)
    return name, command_type, result, ostype

async def execute_command_with_lock(cmd, ostype, socket_path, name, command_type):
    async with lock:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, execute_command_sync, cmd, ostype, socket_path)
        #print(result)
        if not result:
            result = 'NONE'
        if result == 'err':
            result = "NONE"
        #print('return', name)
        return name, command_type, result, ostype

def remove_ansi_sequences(text):
    ansi_escape = re.compile(r'''
        \x1B  # ESC
        (?:   # 7-bit C1 Fe (except CSI)
            [@-Z\\-_]
        |     # or [ for CSI, followed by a control sequence
            \[
            [0-?]*  # Parameter bytes
            [ -/]*  # Intermediate bytes
            [@-~]   # Final byte
        )
    ''', re.VERBOSE)
    return ansi_escape.sub('', text)





mac_address_pattern = re.compile(r'(?:[0-9a-fA-F]:?){12}')
IP = "127.0.0.1"
#port = 30491
USER_NAME = "admin"
USER_PASS = "123"
# Пары логин/пароль, которые пробуем по очереди: основная и admin без пароля
# (заводской RouterOS). После неудачной попытки консоль снова показывает
# Login:, так что следующую пару можно вводить сразу.
MTK_CREDENTIALS = [(USER_NAME, USER_PASS), (USER_NAME, '')]
MTK_PROMPT = "] >"  # Пример приглашения командной строки MikroTik
# Приглашение в любом подменю ("[admin@MikroTik] /ip address>"): если студент
# оставил сессию не в корне меню, "] >" в потоке не встретится
MTK_ANY_PROMPT = r'\[[^\]\r\n]+\][^\r\n]*>'
# Маркер конца вывода скрипта опроса. В самом скрипте печатается склейкой
# (:put ("===MTKDONE" . "===")), чтобы эхо ввода не совпало с маркером
MTK_DONE = '===MTKDONE==='
# Список секций скрипта опроса: при неудаче словарь секций заполняется
# пустыми списками, чтобы дальнейшие проверки не падали на KeyError
MTK_SECTIONS = ('DHCLI', 'IPROUTE', 'INTERFACE', 'DEFGW', 'IPADDR', 'DNS', 'FWNAT', 'HOSTNAME', 'EXPORT')
CONTIMEOUT = 5  # Таймаут ожидания подключения
EXPTIMEOUT = 3  # Таймаут ожидания ответа
MTKSCRIPTTIMEOUT = 30  # Максимальное время выполнения скрипта опроса (включая /export)
MTKLOGINTIMEOUT = 60   # Общий дедлайн процедуры входа


cisusername = 'cisco'
cispassword = 'cisco'
cissecret = 'cisco'
cisconntimeout = 3     # Maximum time for console connection
cisexpctimeout = 15     # Maximum time for each short expect
cislongtimeout = 30    # Maximum time for each long expect
cistimeout = 60        # Maximum run time (conntimeout is included)

def clear_buffer(handler):
    ''' Очищаем входной буфер '''
    try:
        handler.read_nonblocking(size=1000000, timeout=1)  # Чтение всех доступных данных
    except pexpect.exceptions.TIMEOUT:
        pass  # Игнорируем таймаут, так как нас интересует только очистка буфера

def node_quit(handler):
    ''' Отправляем команду /quit '''
    handler.sendline('/quit\r\n')

def node_mtkclose(handler):
    ''' Закрываем telnet-процесс (идемпотентно, безопасно для мёртвого handler) '''
    try:
        handler.close(force=True)
    except Exception:
        pass

def node_login(handler, depth=0):
    ''' Отправляем пустую строку и ожидаем приглашение к входу '''
    if depth > 2:
        # Защита от зацикливания /quit -> повторный вход
        return False
    # Общий дедлайн: молчащая консоль раньше крутила этот цикл вечно,
    # оставляя /tmp/chk.lock висеть до перезапуска сервиса
    deadline = time.time() + MTKLOGINTIMEOUT
    i = -1
    while i == -1:
        if time.time() > deadline:
            print('ERROR: mikrotik login deadline exceeded.')
            return False
        try:
            handler.sendline('\r\n')
            i = handler.expect(['Login:', MTK_PROMPT, MTK_ANY_PROMPT], timeout=CONTIMEOUT)
        except pexpect.exceptions.TIMEOUT:
            i = -1
        except (pexpect.exceptions.EOF, OSError):
            # Мёртвый telnet (порт не отвечает) раньше ронял всю проверку
            print('ERROR: mikrotik console connection closed.')
            return False

    if i == 0:
        # Пробуем пары логин/пароль по очереди
        for user, password in MTK_CREDENTIALS:
            rc = node_trylogin(handler, user, password)
            if rc == 'ok':
                return True
            if rc == 'err':
                return False
            # rc == 'badpass': консоль снова на Login: — пробуем следующую пару
        print('ERROR: all credentials rejected.')
        return False
    else:
        # Открыта чужая сессия (возможно, в подменю) — /quit и повторяем вход
        node_quit(handler)
        return node_login(handler, depth + 1)

def node_trylogin(handler, user, password):
    ''' Одна попытка входа с приглашения Login:.

    Возвращает 'ok' (вошли), 'badpass' (снова Login: — пара не подошла,
    можно пробовать следующую) или 'err' (консоль повела себя неожиданно).
    '''
    handler.send(user + '+c512wt')
    handler.send('\r\n')
    try:
        handler.expect('Password:', timeout=EXPTIMEOUT)
    except pexpect.exceptions.TIMEOUT:
        print('ERROR: error waiting for "Password:" prompt.')
        return 'err'
    handler.sendline(password)
    handler.send('\r\n')
    try:
        j = handler.expect(['Login:', MTK_PROMPT, r'\[Y/n\]'], timeout=CONTIMEOUT)
    except (pexpect.exceptions.TIMEOUT, pexpect.exceptions.EOF):
        # Раньше TIMEOUT здесь не ловился и исключение роняло всю проверку
        print('ERROR: error waiting for prompt after password.')
        return 'err'
    if j == 0:
        # Снова Login: — пароль не подошёл
        return 'badpass'
    if j == 2:
        # Вопрос про просмотр лицензии при первом входе на свежем RouterOS
        handler.sendline('n')
        try:
            handler.expect(MTK_PROMPT, timeout=CONTIMEOUT)
        except (pexpect.exceptions.TIMEOUT, pexpect.exceptions.EOF):
            print('ERROR: error waiting for prompt after license question.')
            return 'err'
    return 'ok'

def config_get(handler, cmd):
    ''' Отправляем скрипт опроса и читаем вывод до маркера завершения '''
    clear_buffer(handler)
    handler.send(cmd)
    handler.send('\r\n')

    # Ждать приглашение "] >" нельзя: оно встречается уже в эхе ввода, из-за
    # чего вывод обрезался, а 3 секунд на весь скрипт с /export не хватало.
    # Скрипт сам печатает в конце маркер MTK_DONE — ждём его.
    try:
        handler.expect(MTK_DONE, timeout=MTKSCRIPTTIMEOUT)
    except (pexpect.exceptions.TIMEOUT, pexpect.exceptions.EOF):
        print('ERROR: error waiting for script done marker.')
        node_quit(handler)
        return False
    _config = handler.before
    node_quit(handler)
    log('routeros get out', _config)
    return _config



def run_on_routeros(cmd, port):
    handler = pexpect.spawnu(f'telnet {IP} {port}', maxread=100000)
    try:
        if node_login(handler):
            print("Login successful!")
            return config_get(handler, cmd)
        return False
    finally:
        # Закрываем telnet и на успехе, и на ошибке — раньше процесс
        # оставался висеть и держал консоль
        node_mtkclose(handler)

def read_json_file(file_path):
    if not os.path.exists(file_path):
        return None 
    data = []
    with open(file_path, 'r') as file:
        for line in file:
            try:
                json_object = json.loads(line.strip())
                data.append(json_object)
            except json.JSONDecodeError as e:
                print(f"Ошибка декодирования JSON {file_path}: {e}")
                return(f"ERRR {file_path}: {e}")
    return data


def node_ciscoenable(handler, secret=None):
    ''' Поднимаемся из user exec (>) в privileged exec (#), вводя enable-пароль при необходимости '''
    # secret задаётся подсказкой лабы (cisco_pass:...); None — дефолтный cissecret
    if secret is None:
        secret = cissecret
    handler.sendline('enable')
    try:
        j = handler.expect(['Password:', '#'], timeout = cisexpctimeout)
    except:
        print('ERROR: error waiting for ["Password:", "#"] prompt.')
        node_ciscoquit(handler)
        return False
    if j == 0:
        handler.sendline(secret)
        try:
            handler.expect('#', timeout = cisexpctimeout)
        except:
            print('ERROR: error waiting for "#" prompt after enable password.')
            node_ciscoquit(handler)
            return False
    return True

def node_ciscologin(handler, secret=None):
    # secret прокидывается в node_ciscoenable (enable-пароль из подсказки лабы)
    # Send an empty line, and wait for the login prompt.
    # Общий дедлайн cistimeout: мёртвая консоль (EOF, молчание, незнакомый prompt)
    # иначе крутила бы этот цикл вечно в executor-потоке вместе с /tmp/chk.lock.
    deadline = time.time() + cistimeout
    i = -1
    while i == -1:
        if time.time() > deadline:
            print('ERROR: login deadline exceeded.')
            node_ciscoquit(handler)
            return False
        try:
            handler.sendline('\r\n')
            i = handler.expect([
                'Username:',
                'Password:',
                '\(config',
                '>',
                '#',
                'Would you like to enter the'], timeout = 5)
        except pexpect.exceptions.TIMEOUT:
            i = -1
        except (pexpect.exceptions.EOF, OSError):
            print('ERROR: console connection closed.')
            node_ciscoquit(handler)
            return False

    if i == 0:
        # Need to send username and password (login local / aaa)
        handler.sendline(cisusername)
        try:
            handler.expect('Password:', timeout = cisexpctimeout)
        except:
            print('ERROR: error waiting for "Password:" prompt.')
            node_ciscoquit(handler)
            return False

        handler.sendline(cispassword)
        try:
            j = handler.expect(['>', '#'], timeout = cisexpctimeout)
        except:
            print('ERROR: error waiting for [">", "#"] prompt.')
            node_ciscoquit(handler)
            return False

        if j == 0:
            return node_ciscoenable(handler, secret)
        return True
    elif i == 1:
        # Пароль на линии (line con 0 + password/login) — приглашение без Username
        handler.sendline(cispassword)
        try:
            j = handler.expect(['>', '#'], timeout = cisexpctimeout)
        except:
            print('ERROR: error waiting for [">", "#"] prompt after line password.')
            node_ciscoquit(handler)
            return False
        if j == 0:
            return node_ciscoenable(handler, secret)
        return True
    elif i == 2:
        # Config mode detected, need to exit
        handler.sendline('end')
        try:
            handler.expect('#', timeout = cisexpctimeout)
        except:
            print('ERROR: error waiting for "#" prompt.')
            node_ciscoquit(handler)
            return False
        return True
    elif i == 3:
        # Need higher privilege
        return node_ciscoenable(handler, secret)
    elif i == 4:
        # Nothing to do
        return True
    elif i == 5:
        # First boot detected
        handler.sendline('no')
        try:
            handler.expect('Press RETURN to get started', timeout = cislongtimeout)
        except:
            print('ERROR: error waiting for "Press RETURN to get started" prompt.')
            node_ciscoquit(handler)
            return False
        handler.sendline('\r\n')
        try:
            handler.expect('Switch>', timeout = cisexpctimeout)
        except:
            print('ERROR: error waiting for "Switch> prompt.')
            node_ciscoquit(handler)
            return False
        handler.sendline('enable')
        try:
            handler.expect('Switch#', timeout = cisexpctimeout)
        except:
            print('ERROR: error waiting for "Switch# prompt.')
            node_ciscoquit(handler)
            return False
        return True
    else:
        # Unexpected output
        node_ciscoquit(handler)
        return False





def node_ciscoquit(handler):
    # Разлогиниваем консоль и закрываем telnet. Вызывается и на успехе, и на
    # ошибках (может быть вызван дважды) — поэтому все шаги защищены.
    try:
        if handler.isalive():
            # 'exit' завершает exec-сессию на консоли, чтобы после проверки
            # не оставалась открытая привилегированная сессия без пароля
            handler.sendline('exit')
            time.sleep(0.3)
    except Exception:
        pass
    try:
        handler.close(force=True)
    except Exception:
        pass





def config_ciscoget(handler):
    # Clearing all "expect" buffer
    while True:
        try:
            handler.expect('#', timeout = 0.1)
        except:
            break

    # Disable paging
    handler.sendline('terminal length 0')
    try:
        handler.expect('#', timeout = cisexpctimeout)
    except:
        print('ERROR: error waiting for "#" prompt.')
        node_ciscoquit(handler)
        return False

    # term shell включает shell processing и должен идти ДО первого echo,
    # иначе echo — неизвестная команда и маркер секции не печатается
    handler.sendline('term shell')
    handler.sendline('terminal width 500')
    handler.sendline('echo VLAN ===START===')
    handler.sendline('show vlan brief')
    handler.sendline('echo IPINT ===START===')
    handler.sendline('show ip int')
    handler.sendline('echo INTSTAT ===START===')
    handler.sendline('show int status')
    handler.sendline('echo TRUNK ===START===')
    handler.sendline('sh int trunk')
    handler.sendline('echo RUNCONF ===START===')
    handler.sendline('show running-config')
    try:
        handler.expect('!\r\nend\r\n', timeout = cislongtimeout)
    except:
        print('ERROR: error waiting for "end" marker.')
        node_ciscoquit(handler)
        return False
    config = handler.before
    #.decode()

    # Manipulating the config
    config = re.sub('\r', '', config, flags=re.DOTALL)                                      # Unix style
    config = re.sub('Ports\n', '', config, flags=re.DOTALL)    # Header
    # config = re.sub('.*[0-9]+ bytes\n', '', config, flags=re.DOTALL)    # Header

    config = re.sub('.*more system:running-config\n', '', config, flags=re.DOTALL)          # Header
    config = re.sub('!\nend.*', '!\nend\n', config, flags=re.DOTALL)                        # Footer
    print(config)
    script_OUT = {}
    current_section = None
    for outline in config.splitlines():
        if '#' not in outline and 'echo ' not in outline and '. ' not in outline:
            i = outline
            if 'Native vlan' not in i and 'act/unsup' not in i and 'Speed Type' not in i and 'VLAN Name' not in i and i != '' and '!' not in i and '^C' not in i and 'Cisco Systems Confidential' not in i and 'banner' not in i and 'Supplemental End User License Restrictions' not in i and 'Last configuration change' not in i and 'configuration' not in i:
                if "===START===" in outline:
                    # Если начинается новая секция и предыдущая секция не пуста, обновляем current_section
                    if current_section is not None and not script_OUT[current_section]:
                        script_OUT[current_section].append("NONE")
                    current_section = outline.split(" ")[0].strip("===")
                    script_OUT[current_section] = []
                elif current_section is not None:
                    script_OUT[current_section].append(outline)
    dict_of_cisco_script = script_OUT
    return dict_of_cisco_script

def run_on_viosl2(handler, secret=None):
    rc = node_ciscologin(handler, secret)
    if rc != True:
        print('ERROR: failed to login.')
        node_ciscoquit(handler)
        return ['err', 'login']
    config = config_ciscoget(handler)
    # Закрываем сессию и на успешном пути: раньше telnet оставался висеть,
    # а консоль — в privileged mode
    node_ciscoquit(handler)
    if config in [False, None]:
        print('ERROR: failed to retrieve config.')
        return ['err', 'output']

    return config

async def execute_command_cisco(handler, name, secret=None):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, run_on_viosl2, handler, secret)
    if not result:
        result = 'NONE'
    if result == 'err':
        result = "NONEERR"
    return name, result

async def execute_command_routeros(cmd, port, name):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, run_on_routeros, cmd, port)
    if not result:
        result = 'NONE'
    if result == 'err':
        result = "NONEERR"
    return name, result
############################################################ ROUTEROS

############################################################ L2 MULTISWITCH
# Проверка распределения узлов по VLAN на управляемых коммутаторах (viosl2
# и IOL L2), в том числе при нескольких свитчах с транками между ними.
# Самостоятельный блок: свитчи опрашиваются повторно, независимо от
# основного прохода.
#
# Подсказка задаётся преподавателем в <description> лабы (.unl) — группы
# вхождения в VLAN в скобках, опционально с номером VLAN через двоеточие:
#   (A, B, R) (C,D,R) (E,R)      — проверяется только разбиение
#   (10: A,B,R) (20: C,D,R)      — дополнительно проверяются сами номера
# Если подсказки нет, группы выводятся из имён узлов, подключённых к
# коммутаторам (guess_l2_groups_by_names): mgr1/mgr2, adm1..adm3, buh1 ->
# группы mgr, adm, buh; роутер (R, R1, router2) добавляется в каждую группу.
# Узел, входящий в несколько групп (роутер), может сидеть на trunk-порту.
# STP/VTP/native vlan сознательно не проверяются: топологии без избыточных
# связей.

# Роутер по имени: R, R1, router, Router2, r-1 и т.п. (регистр не важен)
ROUTER_NAME_RE = re.compile(r'^(?:r|router)[-_]?\d*$', re.IGNORECASE)

def guess_l2_groups_by_names(node_names):
    """Fallback, когда в описании лабы нет подсказки: группы VLAN по префиксам
    имён узлов, подключённых к коммутаторам.

    Префикс — имя в нижнем регистре без хвостовых цифр и разделителей -/_:
    mgr1, mgr2 -> mgr; pc-adm-1 -> pc-adm; admin (без цифр) — сам себе
    префикс, поэтому adm1..adm3 и admin — РАЗНЫЕ группы. Роутеры (по
    ROUTER_NAME_RE) не образуют групп, а добавляются участником в каждую.
    Меньше двух групп — делить нечего (это не VLAN-лаба), возвращаем [].
    """
    routers = sorted(n for n in node_names if ROUTER_NAME_RE.match(n.strip()))
    by_prefix = {}
    for name in sorted(node_names):
        if name in routers:
            continue
        prefix = re.sub(r'\d+$', '', name.strip().lower()).rstrip('-_')
        if not prefix:
            continue
        by_prefix.setdefault(prefix, []).append(name)
    if len(by_prefix) < 2:
        return []
    return [{'vlan': None, 'members': members + routers}
            for _prefix, members in sorted(by_prefix.items())]

def l2_switch_names(dict_of_name_and_ostype, unl_nodes):
    """Имена управляемых коммутаторов лабы: vIOS-L2 всегда; IOL — если образ
    похож на L2 (или образ в лабе не указан: тогда лучше попробовать
    опросить, чем молча пропустить). IOL L3-роутеры отсекаются по image."""
    switches = []
    for name, t in dict_of_name_and_ostype.items():
        if t == 'viosl2':
            switches.append(name)
        elif t == 'iol':
            image = (unl_nodes.get(name) or {}).get('image', '')
            if not image or 'l2' in image.lower():
                switches.append(name)
    return switches

def parse_l2_hint(lab_file):
    """Читает L2-подсказку из <description> файла лабы.

    Возвращает список групп [{'vlan': int|None, 'members': [имена]}].
    Пустой список — подсказки нет, L2-проверка не выполняется.
    """
    try:
        with open(lab_file, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError as e:
        log('parse_l2_hint read err', e)
        return []
    m = re.search(r'<description>(.*?)</description>', content, re.DOTALL)
    if not m:
        return []
    groups = []
    for grp in re.findall(r'\(([^)]*)\)', m.group(1)):
        vlan = None
        body = grp
        vm = re.match(r'\s*(\d+)\s*:\s*(.*)$', grp, re.DOTALL)
        if vm:
            vlan = int(vm.group(1))
            body = vm.group(2)
        members = [x.strip() for x in body.split(',') if x.strip()]
        if members:
            groups.append({'vlan': vlan, 'members': members})
    return groups

def parse_cisco_pass(lab_file):
    """Читает enable-пароль из <description> лабы, если он там задан.

    Преподаватель может дописать в описание маркер 'cisco_pass:MyPASS'
    (регистр слова не важен, пробелы вокруг двоеточия допустимы). Пароль —
    последовательность непробельных символов после двоеточия.

    Возвращает строку пароля либо None, если маркера нет. При None вызывающий
    код работает как раньше — с дефолтным cissecret.
    """
    try:
        with open(lab_file, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError as e:
        log('parse_cisco_pass read err', e)
        return None
    m = re.search(r'<description>(.*?)</description>', content, re.DOTALL)
    if not m:
        return None
    pm = re.search(r'cisco_pass\s*:\s*(\S+)', m.group(1), re.IGNORECASE)
    if pm:
        return pm.group(1)
    return None

def parse_vlan_list(text):
    """'1,10,20-22' -> {1, 10, 20, 21, 22}; 'none' -> пустое множество."""
    vlans = set()
    for part in text.split(','):
        part = part.strip()
        if '-' in part:
            a, _, b = part.partition('-')
            if a.strip().isdigit() and b.strip().isdigit():
                vlans.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            vlans.add(int(part))
    return vlans

def parse_vlan_brief(lines):
    """Секция VLAN (show vlan brief) -> {vlan_id: множество access-портов}.

    Наличие vlan в словаре означает, что он создан и активен; trunk-порты
    в этом выводе не перечисляются.
    """
    vlans = {}
    for line in lines:
        m = re.match(r'^(\d+)\s+\S+\s+active\s*(.*)$', line.strip())
        if m:
            ports = {p.strip() for p in m.group(2).split(',') if p.strip()}
            vlans[int(m.group(1))] = ports
    return vlans

def parse_int_trunk(lines):
    """Секция TRUNK (show int trunk) -> {порт: множество vlan (allowed and active)}.

    Берём блок "Vlans allowed and active": он требует, чтобы vlan был и
    разрешён на транке, и создан на этом свитче. Заголовок первого блока
    (со словами 'Native vlan') отфильтрован ещё при съёме конфига.
    """
    trunks = {}
    section = 'status'
    for line in lines:
        s = line.strip()
        if s.startswith('Port '):
            if 'allowed and active' in s:
                section = 'active'
            else:
                section = 'other'
            continue
        parts = s.split()
        if not parts:
            continue
        if section == 'status' and 'trunking' in parts:
            trunks.setdefault(parts[0], set())
        elif section == 'active' and len(parts) >= 2 and parts[0] in trunks:
            trunks[parts[0]] = parse_vlan_list(parts[1])
    return trunks

def parse_int_status(lines):
    """Секция INTSTAT (show int status) -> {порт: статус}.

    Статусы: connected / notconnect / disabled (shutdown) / err-disabled...
    Статус ищем по известным токенам, потому что колонка Name может быть
    пустой или содержать пробелы.
    """
    statuses = {}
    known = ('connected', 'notconnect', 'disabled', 'err-disabled', 'suspended', 'monitoring')
    for line in lines:
        parts = line.split()
        if not parts or not re.match(r'^[A-Za-z]{2,4}\d+/\d+$', parts[0]):
            continue
        status = next((p for p in parts[1:] if p in known), None)
        if status:
            statuses[parts[0]] = status
    return statuses

def build_switch_links(switch_names, dict_of_name_and_intname, bridges, iol_iface_names=None):
    """Схема подключений по линукс-бриджам (tap vunlX_N <-> сосед по бриджу).

    Возвращает:
      links:    {свитч: {'GiA/B': [имена соседей по бриджу]}}
      sw_links: [(свитч1, порт1, свитч2, порт2)] — линки между свитчами
      facing:   {узел: [(его tap, свитч, порт свитча)]} — точки подключения
                не-свитчевых узлов к свитчам
    Номер интерфейса N из имени tap переводится в имя порта vIOS-L2
    (4 порта на модуль): N=5 -> Gi1/1. Для IOL-свитчей (iol_iface_names =
    {свитч: {N: 'e0/0'}}) имя порта берётся из лабы и приводится к виду
    show-команд ('Et0/0'); если в лабе имени нет — Et{N//4}/{N%4}.
    """
    iol_iface_names = iol_iface_names or {}
    tap_owner = {}
    for vmname, taps in dict_of_name_and_intname.items():
        for tap in taps:
            tap_owner[tap] = vmname

    def portname(tap):
        n = int(tap.split('_')[1])
        if tap_owner.get(tap) in iol_iface_names:
            raw = iol_iface_names[tap_owner[tap]].get(n)
            if raw:
                m = re.match(r'^[A-Za-z]+(\d+/\d+)$', raw.strip())
                if m:
                    return 'Et' + m.group(1)
            return f'Et{n // 4}/{n % 4}'
        return f'Gi{n // 4}/{n % 4}'

    links = {sw: {} for sw in switch_names}
    sw_links = []
    facing = {}
    for ports in bridges.values():
        vunl = [p for p in ports if p.startswith('vunl') and p in tap_owner]
        sw_taps = [t for t in vunl if tap_owner[t] in switch_names]
        for tap in sw_taps:
            owner = tap_owner[tap]
            pname = portname(tap)
            peers = [tap_owner[t] for t in vunl if t != tap]
            links[owner][pname] = peers
            for t in vunl:
                if t != tap and tap_owner[t] not in switch_names:
                    facing.setdefault(tap_owner[t], []).append((t, owner, pname))
        for a in range(len(sw_taps)):
            for b in range(a + 1, len(sw_taps)):
                t1, t2 = sw_taps[a], sw_taps[b]
                sw_links.append((tap_owner[t1], portname(t1), tap_owner[t2], portname(t2)))
    return links, sw_links, facing

def build_l2_domains(l2res, bridges, dict_of_name_and_intname, dict_of_subints):
    """Подменяет физические бриджи синтетическими VLAN-доменами по подсказке.

    Бриджи, в которых участвует порт коммутатора, удаляются (это точечные
    линки "узел-порт свитча", как широковещательные домены они бессмысленны);
    вместо них создаётся по псевдобриджу на каждую группу подсказки:
      - клиент попадает в домен своей группы своим tap'ом (по задуманной
        топологии, независимо от фактического vlan порта — за фактическое
        размещение уже наказывает vlan_membership);
      - роутер-на-палочке — виртуальным сабинтерфейсом tap.vlanid;
      - роутер с отдельными ногами в свитчи — тем tap'ом, чей порт свитча
        фактически находится в vlan группы (разрешение неоднозначности).
    Бриджи без участия свитча (p2p-линки, pnet0) сохраняются как есть.

    Возвращает (новые бриджи, сообщения для отчёта, router_int_result):
    router_int_result — (score, max) проверки "роутер присутствует в каждом
    своём VLAN-домене" (изоляция сети базовой проверкой не покрывается),
    либо None, если в подсказке нет узлов из нескольких групп.
    """
    switches = set(l2res['switches'])
    switch_taps = set()
    for sw in switches:
        switch_taps.update(dict_of_name_and_intname.get(sw, []))

    new_bridges = {}
    for bname, ports in bridges.items():
        if not switch_taps & set(ports):
            new_bridges[bname] = ports

    errs = []
    r_total = 0
    r_wrong = 0
    member_count = Counter(m for g in l2res['groups'] for m in g['members'])
    for idx, g in enumerate(l2res['groups'], 1):
        vid = g['vlan']
        domain = f'vlan{vid}' if vid else f'vlangroup{idx}'
        dports = []
        for member in g['members']:
            if member in switches:
                continue
            contributed = False
            for tap, sw, pname in l2res['facing'].get(member, []):
                subints = dict_of_subints.get(tap, {})
                if vid and vid in subints:
                    # роутер-на-палочке: в домен идёт сабинтерфейс нужного vlan
                    dports.append(subints[vid])
                    contributed = True
                elif subints:
                    # у ноги есть сабинтерфейсы, но не в vlan этой группы —
                    # роутеру нечем присутствовать в домене; физический tap
                    # добавлять нельзя: он выведен из проверок как безадресный
                    # родитель сабинтерфейсов
                    continue
                elif member_count[member] > 1 and vid:
                    # несколько ног в свитчи: берём tap, чей порт фактически
                    # в vlan группы (access или trunk с этим vlan)
                    data = l2res['switch_data'].get(sw, {})
                    if pname in data.get('vlans', {}).get(vid, set()) or vid in data.get('trunks', {}).get(pname, set()):
                        dports.append(tap)
                        contributed = True
                else:
                    dports.append(tap)
                    contributed = True
            # Изоляция: узел из нескольких групп (роутер) обязан присутствовать
            # в каждом своём домене — сабинтерфейсом или отдельной ногой
            if member_count[member] > 1:
                r_total += 1
                if not contributed:
                    r_wrong += 1
                    if vid:
                        errs.append(f'L2: VLAN {vid} (группа: {", ".join(g["members"])}) — у {member} нет интерфейса в этом VLAN, сеть изолирована от маршрутизатора')
        if dports:
            new_bridges[domain] = sorted(set(dports))

    # Лишние сабинтерфейсы: vlan id, не соответствующий ни одной группе узла
    # (недостающие уже покрыты сообщением об изоляции выше)
    member_vlans = {}
    for g in l2res['groups']:
        for member in g['members']:
            member_vlans.setdefault(member, set()).add(g['vlan'])
    for member, flist in l2res['facing'].items():
        expected = {v for v in member_vlans.get(member, set()) if v}
        for tap, _sw, _pname in flist:
            for svid in sorted(dict_of_subints.get(tap, {})):
                if svid not in expected:
                    errs.append(f'L2: у {member} сабинтерфейс в VLAN {svid}, не соответствующий ни одной группе задания')

    router_int_result = (r_total - r_wrong, r_total) if r_total else None
    return new_bridges, errs, router_int_result

async def check_l2_vlans(lab_file, dict_of_name_and_ostype, dict_of_name_and_intname, dict_of_name_and_path, bridges):
    """Проверка L2: распределение узлов по VLAN и транки между коммутаторами.

    Возвращает None, если нет свитчей либо не удалось получить группы (нет
    подсказки в описании и по именам узлов их не вывести), иначе dict:
      {'membership': (score, max), 'trunks': (score, max) или None,
       'errors': [сообщения для отчёта], 'debug': {...}}
    """
    unl_nodes = parse_unl_nodes(lab_file)
    switches = l2_switch_names(dict_of_name_and_ostype, unl_nodes)
    if not switches:
        return None

    # Имена портов IOL-свитчей — из лабы (для сопоставления с show-командами)
    iol_iface_names = {sw: (unl_nodes.get(sw) or {}).get('iface_names', {})
                       for sw in switches
                       if (unl_nodes.get(sw) or {}).get('template') == 'iol'}
    links, sw_links, facing = build_switch_links(switches, dict_of_name_and_intname,
                                                 bridges, iol_iface_names)

    known = set(dict_of_name_and_ostype)
    groups = parse_l2_hint(lab_file)
    # Скобки из обычного текста описания (ни одного известного имени) — не подсказка
    groups = [g for g in groups if any(m in known for m in g['members'])]
    groups_source = 'hint'
    if not groups:
        # Подсказки нет — пробуем вывести группы из имён узлов, подключённых
        # к коммутаторам (mgr1/mgr2, adm1..adm3, ... + роутер в каждую)
        groups = guess_l2_groups_by_names(set(facing))
        groups_source = 'names'
        if groups:
            log('l2 groups guessed by names', groups)
    if not groups:
        return None

    errs = []

    # enable-пароль из описания лабы (cisco_pass:...); None — дефолтный cissecret
    cisco_secret = parse_cisco_pass(lab_file)
    if cisco_secret is not None:
        log('l2 cisco enable password from description hint', '')

    # Повторный опрос свитчей, независимый от основного прохода
    tasks = []
    for name in switches:
        path = dict_of_name_and_path.get(name)
        if not path:
            errs.append(f'L2: у коммутатора {name} не найден путь к консоли')
            continue
        if path.startswith('iol:'):
            # IOL: в path лежит сразу телнет-порт консоли (см. start_bridge)
            port = int(path.split(':', 1)[1])
        else:
            port = int(path.split('/')[1]) + 30000
        handler = pexpect.spawnu(f'telnet 127.0.0.1 {port}', maxread=100000)
        tasks.append(asyncio.ensure_future(execute_command_cisco(handler, name, cisco_secret)))
    switch_data = {}
    switch_hostnames = {}
    for name, sections in await asyncio.gather(*tasks):
        if isinstance(sections, dict) and sections.get('VLAN'):
            switch_data[name] = {
                'vlans': parse_vlan_brief(sections['VLAN']),
                'trunks': parse_int_trunk(sections.get('TRUNK', [])),
                'intstat': parse_int_status(sections.get('INTSTAT', [])),
            }
            # Хостнейм свитча — из строки "hostname X" секции RUNCONF;
            # уходит в общую проверку "Имена узлов"
            switch_hostnames[name] = 'NONE'
            for line in sections.get('RUNCONF', []):
                m = re.match(r'\s*hostname\s+(\S+)', line)
                if m:
                    switch_hostnames[name] = m.group(1)
                    break
        else:
            errs.append(f'L2: не удалось опросить коммутатор {name}')
            switch_hostnames[name] = 'NONE'

    # Порты свитчей, за которыми сидит каждый не-свитчевый узел
    node_ports = {}
    for sw, ports in links.items():
        for pname, peers in ports.items():
            for peer in peers:
                if peer not in switches:
                    node_ports.setdefault(peer, []).append((sw, pname))

    # VLAN каждой группы: из подсказки, иначе выводим из фактических
    # access-портов участников (самый частый; vlan 1 не считаем — это
    # "ничего не настроено"; один и тот же vlan двум группам не отдаём)
    used_vlans = set(g['vlan'] for g in groups if g['vlan'])
    for g in groups:
        if g['vlan'] is not None:
            continue
        cnt = Counter()
        for member in g['members']:
            for sw, pname in node_ports.get(member, []):
                for vid, aports in switch_data.get(sw, {}).get('vlans', {}).items():
                    if pname in aports and vid != 1:
                        cnt[vid] += 1
        for vid, _ in cnt.most_common():
            if vid not in used_vlans:
                g['vlan'] = vid
                used_vlans.add(vid)
                break
        if g['vlan'] is None:
            errs.append(f'L2: не удалось определить VLAN группы ({", ".join(g["members"])}) — участники не расставлены по access-портам')

    # Узлы из нескольких групп (роутер) могут сидеть и на trunk-порту
    member_count = Counter(m for g in groups for m in g['members'])

    def node_in_vlan(member, vid):
        for sw, pname in node_ports.get(member, []):
            data = switch_data.get(sw)
            if not data:
                continue
            if pname in data['vlans'].get(vid, set()):
                return True  # access-порт в нужном vlan
            if member_count[member] > 1 and vid in data['trunks'].get(pname, set()):
                return True  # trunk с этим vlan — роутер-на-палочке
        return False

    # Балл за каждое вхождение "узел в группе"
    total = 0
    wrong = 0
    for g in groups:
        vid = g['vlan']
        for member in g['members']:
            total += 1
            if member not in known:
                wrong += 1
                errs.append(f'L2: узел {member} из подсказки не найден в лабе')
            elif vid is None or not node_in_vlan(member, vid):
                wrong += 1
                errs.append(f'L2: {member} не в VLAN {vid if vid else "?"}')

    # Связность каждой группы через транки между свитчами: BFS по линкам,
    # где vlan группы разрешён и активен с обеих сторон
    trunks_result = None
    if len(switches) > 1:
        t_total = 0
        t_wrong = 0
        for g in groups:
            vid = g['vlan']
            hosts = set()
            for member in g['members']:
                for sw, _pname in node_ports.get(member, []):
                    hosts.add(sw)
            if len(hosts) < 2:
                continue  # группа целиком на одном свитче — транки не нужны
            t_total += 1
            if vid is None:
                t_wrong += 1
                continue
            reached = {next(iter(hosts))}
            changed = True
            while changed:
                changed = False
                for sw1, p1, sw2, p2 in sw_links:
                    ok1 = vid in switch_data.get(sw1, {}).get('trunks', {}).get(p1, set())
                    ok2 = vid in switch_data.get(sw2, {}).get('trunks', {}).get(p2, set())
                    if ok1 and ok2:
                        if sw1 in reached and sw2 not in reached:
                            reached.add(sw2)
                            changed = True
                        elif sw2 in reached and sw1 not in reached:
                            reached.add(sw1)
                            changed = True
            if not hosts <= reached:
                t_wrong += 1
                errs.append(f'L2: VLAN {vid} не проходит до коммутаторов {", ".join(sorted(hosts - reached))} — проверьте транки')
        if t_total:
            trunks_result = (t_total - t_wrong, t_total)

    # Незадействованные порты коммутаторов должны быть выключены (shutdown).
    # Считаем по свитчу (один элемент = "на свитче все лишние порты погашены"),
    # чтобы полтора десятка портов не задавили весь остальной счёт.
    u_total = 0
    u_wrong = 0
    for sw in switches:
        data = switch_data.get(sw)
        if not data or not data['intstat']:
            continue
        wired = set(links.get(sw, {}))
        u_total += 1
        bad = sorted(p for p, st in data['intstat'].items()
                     if p not in wired and st != 'disabled')
        if bad:
            u_wrong += 1
            errs.append(f'L2: на {sw} не выключены неиспользуемые порты: {", ".join(bad)} (нужен shutdown)')
    unused_result = (u_total - u_wrong, u_total) if u_total else None

    # Выключенные порты, ведущие к узлам задания: настройка vlan может быть
    # верной (show vlan brief показывает и выключенные порты, membership
    # проходит), но узел фактически отрезан от сети — штраф
    port_down = 0
    for member, flist in facing.items():
        if member_count.get(member, 0) == 0:
            continue
        for _tap, sw, pname in flist:
            st = switch_data.get(sw, {}).get('intstat', {}).get(pname)
            if st in ('disabled', 'err-disabled'):
                port_down += 1
                errs.append(f'L2: порт {pname} на {sw} (узел {member}) выключен ({st}) — узел отрезан от сети')

    # Лишние VLAN'ы на коммутаторах — не совпадающие ни с одной группой задания.
    # Просто созданный лишний VLAN — мягкий штраф (vlan_extra); лишний VLAN,
    # назначенный на порт, ведущий к узлу из подсказки, — ошибка конфигурации
    # (vlan_extra_used, штраф ощутимее)
    expected_vlans = {g['vlan'] for g in groups if g['vlan']}
    hinted_nodes = set(member_count)
    extra_plain = 0
    extra_used = 0
    for sw in switches:
        data = switch_data.get(sw)
        if not data:
            continue
        member_ports = {p for p, peers in links.get(sw, {}).items()
                        if any(peer in hinted_nodes for peer in peers)}
        for vid, vports in sorted(data['vlans'].items()):
            if vid == 1 or 1002 <= vid <= 1005 or vid in expected_vlans:
                continue
            used = sorted(vports & member_ports)
            if used:
                extra_used += 1
                errs.append(f'L2: на {sw} лишний VLAN {vid} на порту узла ({", ".join(used)}) — ошибка конфигурации')
            elif vports:
                extra_plain += 1
                errs.append(f'L2: на {sw} лишний VLAN {vid} (порты: {", ".join(sorted(vports))}) — заданию он не соответствует')
            else:
                extra_plain += 1
                errs.append(f'L2: на {sw} создан VLAN {vid}, не соответствующий ни одной группе задания')

    # Порты узлов из подсказки, оставшиеся в VLAN 1 — "порт не настроен"
    for member, plist in node_ports.items():
        if member_count.get(member, 0) == 0:
            continue
        for sw, pname in plist:
            data = switch_data.get(sw)
            if data and pname in data['vlans'].get(1, set()):
                errs.append(f'L2: порт {pname} на {sw} (узел {member}) остался в VLAN 1 — порт не настроен')

    debug = {
        'groups': [{'vlan': g['vlan'], 'members': g['members']} for g in groups],
        # 'hint' — из <description> лабы, 'names' — выведены по именам узлов
        'groups_source': groups_source,
        'iol_switches': sorted(iol_iface_names),
        'links': links,
        'sw_links': sw_links,
        'switch_vlans': {sw: {str(vid): sorted(p) for vid, p in d['vlans'].items()} for sw, d in switch_data.items()},
        'switch_trunks': {sw: {p: sorted(v) for p, v in d['trunks'].items()} for sw, d in switch_data.items()},
    }
    # groups/switches/facing/switch_data нужны шагу подмены L1 -> L2
    # (build_l2_domains) после разбора адресов
    return {'membership': (total - wrong, total), 'trunks': trunks_result,
            'unused': unused_result,
            'extra_vlans': (extra_plain, extra_used),
            'port_down': port_down,
            'hostnames': switch_hostnames,
            'errors': errs, 'debug': debug,
            'groups': groups, 'switches': switches,
            'facing': facing, 'switch_data': switch_data}
############################################################ L2 MULTISWITCH END

def int_of_ostype(i, d1, d2):
    # exit_key обязан быть инициализирован: для инта, не найденного ни у
    # одного узла, функция падала UnboundLocalError и роняла всю проверку
    exit_key = None
    for key, val in d1.items():
        if isinstance(val, list):
            if i in val:
                exit_key = key
        else:
            if i == val:
                exit_key = key
    if exit_key is None:
        return None
    for key, val in d2.items():
        if exit_key == key:
            return val
    return None

def remove_prefix(ip_with_prefix):
    # Убираем префикс, разделяя строку по символу "/"
    return ip_with_prefix.split('/')[0]

def are_ip_addresses_unique(dictionary):
    # Убираем префиксы из всех значений словаря
    ip_addresses = [remove_prefix(ip) for ip in dictionary.values()]
    unique_ip_addresses = set(ip_addresses)
    return len(ip_addresses) == len(unique_ip_addresses)


#
@app.get("/openlab")
async def openlab():
    result = fetch_single_lab_session()
    if len(result) > 1:
        return result[1]
    else:
        return None

async def render_dashboard(request: Request, notice=None, status=None, current_lab=None):
    """Общий рендер дашборда результатов из SQLite.

    current_lab — путь лабы, чью детальную выдачу открыть по умолчанию (например,
    только что проверенная). Если не задан/не найден — открывается самая свежая.
    """
    loop = asyncio.get_event_loop()
    labs = await loop.run_in_executor(None, load_dashboard)
    sel_index = 0
    if current_lab:
        for i, lab in enumerate(labs):
            if lab['lab_path'] == current_lab:
                sel_index = i
                break
    return templates.TemplateResponse("results.html", {
        "request": request,
        "labs": labs,
        "sel_index": sel_index,
        "labels": CHECK_LABELS,
        "username": username,
        "clientip": str(clientip),
        "notice": notice,
        "status": status,
    })

@app.get("/results", response_class=HTMLResponse)
async def results(request: Request):
    return await render_dashboard(request)

# /report оставлен как алиас на новый дашборд ради старых ссылок
@app.get("/report", response_class=HTMLResponse)
async def read_report(request: Request):
    return await render_dashboard(request)

linux_full_cmd = 'echo SSHD ===START;systemctl status ssh|grep -c "Active: active (running)";echo DNSSERVER ===START;systemctl status named|grep -c "Active: active (running)";echo IPADDR ===START;ip -d a || ip a;echo IPROUTE ===START;ip r;echo HOSTNAME ===START;hostname;echo FORWARDING ===START;sysctl net.ipv4.ip_forward;echo DNSCLI ===START;command -v resolvectl >/dev/null && resolvectl status | awk "/Current DNS Server/ {print \"nameserver \" \$NF}" || cat /etc/resolv.conf;echo NFTSERVICE ===START;systemctl status nftables;echo DHCPDINSTALL ===START;dpkg -l |grep -c isc-dhcp-server;echo DHCPDRUN ===START;systemctl status isc-dhcp-server |grep -c "Active: active (running)"'
win_full_cmd = 'chcp 65001 & echo IPADDR ===START & ipconfig & echo IPROUTE ===START & route print -4 & echo HOSTNAME ===START & hostname & echo DNSCLI ===START & netsh interface ipv4 show dns'
#linux_full_cmd = 'echo DNSSERVER ===START;systemctl status named;echo IPADDR ===START;ip a;echo IPROUTE ===START;ip r;echo HOSTNAME ===START;hostname;echo FORWARDING ===START;sysctl net.ipv4.ip_forward;echo DNSCLI ===START;cat /etc/resolv.conf;echo NFTSERVICE ===START;systemctl status nftables;echo DHCPDINSTALL ===START;dpkg -l |grep -c isc-dhcp-server'
linux_nftrules_cmd = 'nft list ruleset'
# Секции, которые обязаны быть в выводе полного скрипта опроса. Если вывод
# с узла пришёл оборванным (например, гонка в qemu-guest-agent на выходе
# процесса), недостающие секции дозаполняются пустышками, чтобы обращение
# к ним не роняло всю проверку KeyError'ом.
LINUX_SECTIONS = ('SSHD', 'DNSSERVER', 'IPADDR', 'IPROUTE', 'HOSTNAME', 'FORWARDING', 'DNSCLI', 'NFTSERVICE', 'DHCPDINSTALL', 'DHCPDRUN')
WIN_SECTIONS = ('IPADDR', 'IPROUTE', 'HOSTNAME', 'DNSCLI')
@app.get("/ping")
async def ping(request: Request, fmt: str = Query('auto')):
    try:
        current_time = datetime.now()
        formatted_time = current_time.strftime("%d.%m.%Y %H:%M")
        if os.path.isfile('/tmp/chk.lock'):
            answer = {}
            answer['errorinfo'] = 'chck is running'
            answer['username'] = username
            answer['time'] = formatted_time
            answer['status'] = 'err'
            forwebresult = {}
            forwebresult.update(answer)

            if username in admin_list or fmt == 'json':
                return forwebresult
            return await render_dashboard(request, notice='Проверка уже выполняется, подождите…', status='err')
        else:
            print('____________________CREATE LOCK FILE')
            open('/tmp/chk.lock', 'a').close()
        
        answer = {}
        errors = {}
        forweb = {}

        # Единый аккумулятор оценок по проверкам: {name: {"score", "max"}}.
        # Перезапись по имени повторяет прежнее поведение forweb (последний выигрывает,
        # напр. в цикле SNAT). Score клампится в [0..max], чтобы тяжёлые штрафы
        # одной проверки не уводили общий счёт в минус. forweb пишем параллельно
        # для обратной совместимости (JSON-возврат админу, /report по result.json).
        checks = {}
        def add_check(name, score, maxv):
            maxv = int(maxv)
            s = max(0, min(int(score), maxv))
            w = CHECK_WEIGHTS.get(name, 1)
            checks[name] = {"score": s * w, "max": maxv * w}
            forweb[name] = f'{s * w} / {maxv * w}'

        # Штрафы: не входят в max, а вычитаются из итога. {name: {"count", "points"}}
        penalties = {}
        def add_penalty(name, count):
            count = int(count)
            if count > 0:
                points = count * PENALTIES.get(name, 0)
                penalties[name] = {"count": count, "points": points}
                forweb[name] = f'штраф -{points}'

        #errors['time'] = formatted_time
        answer['time'] = formatted_time
        #forweb['time'] = formatted_time
        errors['hostnames'] = []
        errors['ipaddrs'] = []
        errors['defaultgw'] = []
        errors['dns'] = []
        errors['multinet_in_l2domain'] = []
        errors['routecount'] = []
        answer['status'] = ''
        errors['errors_noty'] = []
        answer['specout'] = []


        brief = {}
        tasks = []
        routeros_tmps = []
        iptasks = []
        output_dict = {}
        dict_of_name_routeros_script = {}
        dict_of_name_winservers_script = {}
        dict_of_intnames_ipaddr = {}
        # Реальный адрес интерфейса, сохраняется даже когда статус схлопнут в MULTI,
        # чтобы проверка шлюза не «протекала» из-за токенов NONE/MULTI/DOWN.
        dict_of_intnames_realaddr = {}
        dict_of_vmnames_hostname = {}
        dict_of_vmnames_defgw = {}
        dict_of_intnames_network = {}
        dict_of_bridges_vmnames = {}
        dict_of_routers_address = {}
        dict_of_vmnames_dnssrv = {}
        list_of_routers = []
        list_of_networks = []
        lab = fetch_single_lab_session()
        dict_of_name_fullcmd = {}
        dict_of_name_and_nftrules = {}

        # with open('/tmp/user') as f:
        #     username = f.read().strip()

        answer['username'] = username
        forweb['username'] = username


        mikrot_script = """:do {
                :put "===DHCLI START===";
                /ip dhcp-client print;
                :put "===IPROUTE START===";
                /ip route print;
                :put "===INTERFACE START===";
                /interface print;
                :put "===DEFGW START===";
                /ip route print where dst-address="0.0.0.0/0";
                :put "===IPADDR START===";
                /ip address print;
                :put "===DNS START===";
                /ip dns print;
                :put "===FWNAT START===";
                /ip firewall nat print;
                :put "===HOSTNAME START===";
                /system identity print;
                :put "===EXPORT START===";
                /export;
                } on-error={:put "ERRR";};
                :put ("===MTKDONE" . "===")"""




        log('_________________________________', f'START for {username}')
        if lab != 'moreone' and lab != 'no':
            #return(lab[1])
            lab_path = '/opt/unetlab/labs' + str(lab[1])
            answer['lab_path'] = str(lab[1])
            forweb['lab_path'] = str(lab[1])
            dict_of_name_and_ostype, dict_of_vmname_and_uid = find_uuid_in_file_and_ps(lab_path)
            if dict_of_name_and_ostype != 'count' and dict_of_name_and_ostype != 'multilab':
                answer['name_ostype'] = str(dict_of_name_and_ostype)
                # Данные нод из .unl нужны start_bridge, чтобы привязать
                # tap'ы IOL-нод (у них нет процесса qemu)
                unl_nodes = parse_unl_nodes(lab_path)
                dict_of_name_and_path, list_of_vmnames, list_of_intname, dict_of_name_and_intname, bridges = start_bridge(unl_nodes)
                answer['list_of_vmnames'] = str(list_of_vmnames)
                answer['list_of_intname'] = str(list_of_intname)
                answer['dict_of_name_and_intname'] = str(dict_of_name_and_intname)
                answer['dict_of_name_and_path'] = str(dict_of_name_and_path)
                answer['bridges'] = str(bridges)
                answer['dict_of_vmname_and_uid'] = dict_of_vmname_and_uid
                dict_of_intname_and_mac = get_tap_mac_map()
                answer['dict_of_intname_and_mac'] = dict_of_intname_and_mac
                for namenode in dict_of_name_and_ostype:
                    if dict_of_name_and_ostype[namenode] == 'proxmox':
                        dict_of_name_and_ostype[namenode] = 'linux'

                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'linux':
                        task = asyncio.ensure_future(execute_command(linux_full_cmd, 'linux', dict_of_name_and_path[name], name, 'fullcmd'))  
                        tasks.append(task)
                    elif dict_of_name_and_ostype[name] == 'win' or dict_of_name_and_ostype[name] == 'winserver':
                        task = asyncio.ensure_future(execute_command(win_full_cmd, 'windows', dict_of_name_and_path[name], name, 'fullcmd'))
                        tasks.append(task)
                list_of_fullcmdout = await asyncio.gather(*tasks)

                

                for fullcmdout in list_of_fullcmdout:
                    if fullcmdout[2] == 'NONE':
                        os.remove('/tmp/chk.lock')
                        forweb['username'] = username
                        forweb['lab_path'] = "Ошибка чтения сокета"
                        return forweb
                    script_OUT = {}
                    current_section = None
                    if fullcmdout[3] == 'windows':
                        for line in fullcmdout[2].splitlines():
                            if " ===START" in line:
                                    # Если начинается новая секция и предыдущая секция не пуста, обновляем current_section
                                    if current_section is not None and not script_OUT[current_section]:
                                        script_OUT[current_section].append("NONE")
                                    current_section = line.split(" ")[0].strip("===")
                                    script_OUT[current_section] = []
                            elif current_section is not None:
                                if line != '':
                                    script_OUT[current_section].append(line)
                        dict_of_name_fullcmd[fullcmdout[0]] = script_OUT
              
                for fullcmdout in list_of_fullcmdout:
                    script_OUT = {}
                    current_section = None
                    if fullcmdout[3] == 'linux':
                        for line in fullcmdout[2].splitlines():
                            # print(f'host {fullcmdout[0]}: {line}')
                            if " ===START" in line:
                                    # Если начинается новая секция и предыдущая секция не пуста, обновляем current_section
                                    if current_section is not None and not script_OUT[current_section]:
                                        script_OUT[current_section].append("NONE")
                                    current_section = line.split(" ")[0].strip("===")
                                    script_OUT[current_section] = []
                            elif current_section is not None:
                                script_OUT[current_section].append(line)
                        dict_of_name_fullcmd[fullcmdout[0]] = script_OUT

                # Оборванный вывод с узла раньше ронял всю проверку KeyError'ом
                # при первом обращении к отсутствующей секции — дозаполняем
                # пустышками и показываем проблему в отчёте
                for fullcmdout in list_of_fullcmdout:
                    expected = LINUX_SECTIONS if fullcmdout[3] == 'linux' else WIN_SECTIONS
                    secs = dict_of_name_fullcmd.setdefault(fullcmdout[0], {})
                    missing = [s for s in expected if s not in secs]
                    for s in missing:
                        secs[s] = ['NONE']
                    if missing:
                        errors['errors_noty'].append(f'Неполный вывод с узла {fullcmdout[0]}, недостающие разделы: {", ".join(missing)}')
                        log('incomplete fullcmd output', f'{fullcmdout[0]}: {missing}')
                tasks = []
                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'linux':
                        task = asyncio.ensure_future(execute_command(linux_nftrules_cmd, 'linux', dict_of_name_and_path[name], name, 'fullcmd'))  
                        tasks.append(task)
                list_of_nftrules = await asyncio.gather(*tasks)

                for nftrules in list_of_nftrules:
                    tmpout = []
                    for linerules in nftrules[2].splitlines():
                        tmpout.append(linerules.replace('\t', ''))
                    dict_of_name_fullcmd[nftrules[0]]['NFTRULES'] = tmpout

                print('fullcmd done_______________________________')
                answer['dict_of_name_fullcmd']= dict_of_name_fullcmd

                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'linux' or dict_of_name_and_ostype[name] == 'win' or dict_of_name_and_ostype[name] == 'winserver':
                        dict_of_vmnames_hostname[name] = dict_of_name_fullcmd[name]['HOSTNAME'][0]
                answer['dict_of_vmnames_hostname'] = dict_of_vmnames_hostname

                # Коммутаторы (viosl2, IOL L2) здесь больше не опрашиваются:
                # их целиком опрашивает L2-блок (check_l2_vlans), иначе каждый
                # свитч дёргался по консоли дважды за прогон
                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'mikrotik':
                        tmpport = dict_of_name_and_path[name]
                        port = int(tmpport.split('/')[1]) + 30000
                        # run_on_routeros открывает telnet сам; лишний spawnu здесь
                        # оставлял по неиспользуемому подключению на каждый узел
                        routeros_tmp = asyncio.ensure_future(execute_command_routeros(mikrot_script, port, name))
                        routeros_tmps.append(routeros_tmp)

                ipresult = await asyncio.gather(*iptasks)
                routeros_results = await asyncio.gather(*routeros_tmps)
                answer['mikrotik_raw_output'] = routeros_results

                # =============== L2 MULTISWITCH (VLAN) ===============
                # Единственное место опроса коммутаторов; подсказка берётся из
                # <description> лабы. Ошибка внутри блока не роняет остальную
                # проверку. Выполняется до разбора RouterOS: mikrotik-ветке
                # нужен l2res, чтобы зарегистрировать vlan-сабинтерфейсы.
                try:
                    l2res = await check_l2_vlans(lab_path, dict_of_name_and_ostype,
                                                 dict_of_name_and_intname,
                                                 dict_of_name_and_path, bridges)
                except Exception:
                    l2res = None
                    log('check_l2_vlans err', traceback.format_exc())
                if l2res:
                    answer['l2_vlans_debug'] = l2res['debug']
                    errors['errors_noty'].extend(l2res['errors'])
                    add_check('vlan_membership', l2res['membership'][0], l2res['membership'][1])
                    if l2res['trunks']:
                        add_check('vlan_trunks', l2res['trunks'][0], l2res['trunks'][1])
                    if l2res['unused']:
                        add_check('vlan_unused_ports', l2res['unused'][0], l2res['unused'][1])
                    # Штрафы: max не меняют, вычитаются из итога
                    add_penalty('vlan_extra', l2res['extra_vlans'][0])
                    add_penalty('vlan_extra_used', l2res['extra_vlans'][1])
                    add_penalty('vlan_port_shutdown', l2res['port_down'])
                    # Хостнеймы свитчей — в общую проверку "Имена узлов"
                    dict_of_vmnames_hostname.update(l2res['hostnames'])
                # =============== L2 MULTISWITCH (VLAN) END ===============

                dict_of_subints = {}

                for routeros_result in routeros_results:
                    list_router_script_out = []
                    for outline in routeros_result[1].splitlines():
                        if 'Flags:' not in outline and ':put ' not in outline and '#' not in outline:
                            list_router_script_out.append(outline.strip().replace('\r', ''))
                    script_OUT = {}
                    current_section = None
                    for outline in list_router_script_out:
                        if " START===" in outline:
                                # Если начинается новая секция и предыдущая секция не пуста, обновляем current_section
                                if current_section is not None and not script_OUT[current_section]:
                                    script_OUT[current_section].append("Пустая секция")
                                current_section = outline.split(" ")[0].strip("===")
                                script_OUT[current_section] = []
                        elif current_section is not None:
                            script_OUT[current_section].append(outline)
                    dict_of_name_routeros_script[routeros_result[0]] = script_OUT
                    answer['dict_of_name_routeros_script'] = dict_of_name_routeros_script
                    # Кортеж (имя, вывод) всегда истинен, поэтому прежнее условие
                    # "if routeros_result:" не отсекало неудачный опрос: script_OUT
                    # оставался пустым и обращение к ['EXPORT'] роняло проверку.
                    # EXPORT — последняя секция скрипта: если она есть, скрипт дошёл
                    # до конца и все секции гарантированно присутствуют.
                    if script_OUT.get('EXPORT'):

                        dict_routeros_ints_bymac = {}
                        # Хостнейм — первая строка "set name=" из /export; раньше
                        # найденное значение затиралось обратно в 'NONE' каждой
                        # следующей строкой экспорта
                        dict_of_vmnames_hostname[routeros_result[0]] = 'NONE'
                        for line in dict_of_name_routeros_script[routeros_result[0]]['EXPORT']:
                            if 'set name=' in line:
                                dict_of_vmnames_hostname[routeros_result[0]] = line.split('=')[1]
                                break
                        for line in dict_of_name_routeros_script[routeros_result[0]]['INTERFACE']:
                            if mac_address_pattern.search(line.strip()):
                                columns = line.split()
                                # vlan-сабинтерфейсы наследуют MAC родителя и
                                # затирали бы его в карте — берём только
                                # физические порты (столбец типа == ether)
                                if 'ether' not in columns:
                                    continue
                                if mac_address_pattern.search(columns[5]):
                                    macaddr_sample = columns[5].split(':')[5]
                                    log_and_print(f'macaddrsample_____________{macaddr_sample}, columns: {columns}')
                                    answer['macaddrsample_____________'] = f'macaddrsample_____________{macaddr_sample}, columns: {columns}'
                                    if macaddr_sample.isdigit():
                                        print(columns[2], int(macaddr_sample))
                                        
                                        dict_routeros_ints_bymac[int(macaddr_sample)] = columns[2]
                                    else:
                                        kostil = "0"
                                        dict_routeros_ints_bymac[int(kostil)] = columns[2]
                                        mikrot_err_macaddr = 1
                        for intname in dict_of_name_and_intname[routeros_result[0]]:
                            int_number = intname.split('_')[1]
                            # снапшот ключей: pop+add внутри итерации по живому
                            # keys() — RuntimeError на Python 3.8+
                            for key in list(dict_routeros_ints_bymac.keys()):
                                if key == int(int_number):
                                    dict_routeros_ints_bymac[intname] = dict_routeros_ints_bymac.pop(key)
                        unused_ports = []
                        for tmpintname in dict_routeros_ints_bymac.keys():
                            if 'vunl' not in str(tmpintname):
                                unused_ports.append(tmpintname)
                        for tmpintname in unused_ports:
                            dict_routeros_ints_bymac.pop(tmpintname)
                        # vlan-сабинтерфейсы из /export (секция "/interface vlan",
                        # строки "add interface=LAN name=vlan10 vlan-id=10"):
                        # в /interface print их не отличить от родителя по MAC
                        mtk_vlan_subints = []
                        in_vlan_export = False
                        for line in dict_of_name_routeros_script[routeros_result[0]]['EXPORT']:
                            if line.startswith('/'):
                                in_vlan_export = line.strip() == '/interface vlan'
                            elif in_vlan_export and line.startswith('add '):
                                opts = dict(re.findall(r'([\w-]+)=(\S+)', line))
                                if 'interface' in opts and 'name' in opts and opts.get('vlan-id', '').isdigit():
                                    mtk_vlan_subints.append((opts['interface'], opts['name'], int(opts['vlan-id'])))
                        if dict_routeros_ints_bymac:
                            answer['dict_routeros_ints_bymac'] = str(dict_routeros_ints_bymac)
                            # Непустые строки /ip address print; интерфейс — всегда
                            # последний столбец, сравниваем столбец целиком:
                            # подстрочный поиск путал vlan1 с vlan10
                            mtk_addr_lines = [l for l in dict_of_name_routeros_script[routeros_result[0]]['IPADDR'] if l.strip()]

                            def mtk_set_addr(key, ifname):
                                addr_lines = [l for l in mtk_addr_lines if l.split()[-1] == ifname]
                                if len(addr_lines) == 1:
                                    parts = addr_lines[0].split()
                                    dict_of_intnames_ipaddr[key] = parts[2] if len(parts) == 5 else parts[1]
                                    dict_of_intnames_realaddr[key] = dict_of_intnames_ipaddr[key]
                                elif not addr_lines:
                                    dict_of_intnames_ipaddr[key] = "NONE"
                                else:
                                    dict_of_intnames_ipaddr[key] = "MULTI"

                            for int_name_router in dict_routeros_ints_bymac.keys():
                                mtk_set_addr(int_name_router, dict_routeros_ints_bymac[int_name_router])

                            # vlan-сабинтерфейсы регистрируем виртуальным интом
                            # 'tap.vlanid' со своим адресом — базовые проверки
                            # (адреса, сети, шлюзы, дубли) работают с ним как с
                            # обычным. В отличие от linux-ветки не зависим от
                            # l2res: у RouterOS /export даёт vlan-id и адрес
                            # явно, угадывать нечего. dict_of_subints нужен
                            # build_l2_domains'у — он всё равно отработает только
                            # при активном l2res.
                            tracked_ints = len(dict_routeros_ints_bymac)
                            for intname, guest_if in list(dict_routeros_ints_bymac.items()):
                                has_subints = False
                                for vparent, vname, vid in mtk_vlan_subints:
                                    if vparent != guest_if:
                                        continue
                                    has_subints = True
                                    virt = f'{intname}.{vid}'
                                    dict_of_name_and_intname[routeros_result[0]].append(virt)
                                    dict_of_subints.setdefault(intname, {})[vid] = virt
                                    mtk_set_addr(virt, vname)
                                    tracked_ints += 1
                                if has_subints and dict_of_intnames_ipaddr.get(intname) == 'NONE':
                                    # Физический родитель без адреса — норма для
                                    # роутера-на-палочке, не штрафуем его как
                                    # безадресный
                                    dict_of_name_and_intname[routeros_result[0]].remove(intname)
                                    dict_of_intnames_ipaddr.pop(intname, None)
                                    tracked_ints -= 1
                            # Раньше в подсчёт попадала пустая строка-хвост секции,
                            # а адреса vlan-сабинтерфейсов не учитывались вовсе
                            if len(mtk_addr_lines) != tracked_ints:
                                errors['errors_noty'].append(f'Проблемы на {routeros_result[0]}, количество ip адресов не равно колву интов')
                    else:
                        # Заполняем секции пустыми списками: дальше по коду они
                        # индексируются напрямую (DEFGW, DNS, FWNAT, IPROUTE)
                        dict_of_name_routeros_script[routeros_result[0]] = {k: [] for k in MTK_SECTIONS}
                        dict_of_vmnames_hostname[routeros_result[0]] = 'NONE'
                        for intname in dict_of_name_and_intname[routeros_result[0]]:
                            dict_of_intnames_ipaddr[intname] = "NONE"
                        errors['errors_noty'].append(f'Проблемы на {routeros_result[0]}: не удалось войти (пробовали admin/123 и admin без пароля) или прочитать вывод')



                answer['dict_of_vmnames_hostname'] = dict_of_vmnames_hostname
                answer['dict_of_name_routeros_script'] = dict_of_name_routeros_script

                # Заголовок интерфейса из `ip -d a`: имя может содержать точку
                # (ens3.10), у сабинтерфейса после имени идёт @родитель
                interface_pattern = r'^\d+: ([^:@\s]+)(?:@(\S+))?:'
                mac_pattern = r'link/ether (\S+)'
                state_pattern = r'state (\S+)'
                # Строка деталей vlan-сабинтерфейса из `ip -d a` — даёт VLAN ID
                # независимо от нейминга (ens3.10, vlan10, произвольное имя)
                vlanid_pattern = r'vlan protocol 802\.1Q id (\d+)'
                ipv4_pattern = r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)'

                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'linux':
                        gre_present = False
                        linux_ints = {}
                        # Обязательная инициализация: если секция IPADDR пуста или
                        # начинается не с заголовка интерфейса (оборванный вывод,
                        # заглушка 'NONE'), переменная раньше оставалась
                        # неинициализированной и роняла проверку UnboundLocalError,
                        # а между узлами протекало значение прошлой итерации
                        current_interface = None
                        for line in dict_of_name_fullcmd[name]['IPADDR']:
                            if 'gre' in line:
                                gre_present = True
                            # Поиск имени интерфейса
                            interface_match = re.search(interface_pattern, line)
                            if interface_match:
                                current_interface = interface_match.group(1)
                                linux_ints[current_interface] = {"mac": "", "state": "", "ipv4": [], "parent": interface_match.group(2), "vlan": None}

                            # Если имя интерфейса найдено, ищем другие данные
                            if current_interface:
                                mac_match = re.search(mac_pattern, line)
                                state_match = re.search(state_pattern, line)
                                vlan_match = re.search(vlanid_pattern, line)
                                ipv4_matches = re.findall(ipv4_pattern, line)

                                if mac_match:
                                    linux_ints[current_interface]["mac"] = mac_match.group(1)
                                if state_match:
                                    linux_ints[current_interface]["state"] = state_match.group(1)
                                if vlan_match:
                                    linux_ints[current_interface]["vlan"] = int(vlan_match.group(1))
                                if ipv4_matches:
                                    ip_with_mask = []
                                    for ipv4tmp in ipv4_matches:
                                        ip_with_mask.append(ipv4_matches[0][0] + '/' + ipv4_matches[0][1] )
                                    linux_ints[current_interface]["ipv4"].extend(ip_with_mask)
                        dict_of_name_and_ostype['debug'] = linux_ints

                        # Обратная карта: MAC -> имя интерфейса гостя (из вывода `ip -d a`).
                        # Заменяет угадывание имён (ens3+idx / ens3f{idx} / eth0 для Scan) —
                        # имя интерфейса ищем по MAC из командной строки qemu.
                        # Только физические интерфейсы: vlan-сабинтерфейсы наследуют
                        # MAC родителя и затирали бы его в карте.
                        mac_to_guestif = {
                            data['mac'].lower(): ifname
                            for ifname, data in linux_ints.items()
                            if data['mac'] and not data['parent']
                        }

                        for intname in dict_of_name_and_intname[name]:
                            tap_mac = dict_of_intname_and_mac.get(intname, '').lower()
                            guest_if = mac_to_guestif.get(tap_mac)
                            if not guest_if:
                                # MAC tap'а не нашёлся среди интерфейсов гостя — fallback
                                log('mac match not found', f'{name} {intname} mac={tap_mac}')
                                dict_of_intnames_ipaddr[intname] = "NONE"
                                continue

                            ips = linux_ints[guest_if]['ipv4']
                            if ips:
                                # Реальный адрес сохраняем всегда, даже при MULTI
                                dict_of_intnames_realaddr[intname] = ips[0]
                            if linux_ints[guest_if]['state'] == 'DOWN':
                                dict_of_intnames_ipaddr[intname] = "DOWN"
                            elif len(ips) == 0:
                                dict_of_intnames_ipaddr[intname] = "NONE"
                            elif len(ips) > 1 and not gre_present:
                                dict_of_intnames_ipaddr[intname] = "MULTI"
                            else:
                                dict_of_intnames_ipaddr[intname] = ips[0]

                        # === L2 MULTISWITCH: vlan-сабинтерфейсы (только при активной
                        # подсказке). Каждый сабинтерфейс регистрируется как виртуальный
                        # инт 'tap.vlanid' со своим адресом — дальше базовые проверки
                        # (адреса, сети, шлюзы, дубли) работают с ним как с обычным.
                        if l2res:
                            for intname in list(dict_of_name_and_intname[name]):
                                tap_mac = dict_of_intname_and_mac.get(intname, '').lower()
                                guest_if = mac_to_guestif.get(tap_mac)
                                if not guest_if:
                                    continue
                                has_subints = False
                                for ifname, data in linux_ints.items():
                                    if data['parent'] == guest_if and data['vlan']:
                                        has_subints = True
                                        virt = f'{intname}.{data["vlan"]}'
                                        dict_of_name_and_intname[name].append(virt)
                                        dict_of_subints.setdefault(intname, {})[data['vlan']] = virt
                                        ips = data['ipv4']
                                        if ips:
                                            dict_of_intnames_realaddr[virt] = ips[0]
                                        if data['state'] == 'DOWN':
                                            dict_of_intnames_ipaddr[virt] = 'DOWN'
                                        elif len(ips) == 0:
                                            dict_of_intnames_ipaddr[virt] = 'NONE'
                                        elif len(ips) > 1:
                                            dict_of_intnames_ipaddr[virt] = 'MULTI'
                                        else:
                                            dict_of_intnames_ipaddr[virt] = ips[0]
                                if has_subints and dict_of_intnames_ipaddr.get(intname) == 'NONE':
                                    # Физический родитель без адреса — норма для
                                    # роутера-на-палочке, не штрафуем его как безадресный
                                    dict_of_name_and_intname[name].remove(intname)
                                    dict_of_intnames_ipaddr.pop(intname, None)





                    elif dict_of_name_and_ostype[name] == 'win' or dict_of_name_and_ostype[name] == 'winserver':
                        ip_trigger = '0'
                        gw_trigger = '0'
                        for line in dict_of_name_fullcmd[name]['IPADDR']:

                            if 'IPv4' in line:
                                pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                                winiplist = re.findall(pattern, line)
                                ip_trigger = '1'
                                for winip in winiplist:
                                    dict_of_intnames_ipaddr[dict_of_name_and_intname[name][0]] = winip
                            elif 'Mask' in line:
                                pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                                winmasks = re.findall(pattern, line)
                                for winmask in winmasks:
                                    dict_of_intnames_ipaddr[dict_of_name_and_intname[name][0]] = winip + '/' + str(mask_to_prefix(winmask))
                                    dict_of_intnames_realaddr[dict_of_name_and_intname[name][0]] = winip + '/' + str(mask_to_prefix(winmask))

                            elif 'Default' in line:
                                pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                                defgws = re.findall(pattern, line)
                                gw_trigger = '1'
                                if defgws:
                                    for defgw in defgws:
                                        dict_of_vmnames_defgw[name] = defgw
                                else:
                                    dict_of_vmnames_defgw[name] = 'NONE'
                        if ip_trigger == '0':
                            dict_of_intnames_ipaddr[dict_of_name_and_intname[name][0]] = 'NONE'
                        if gw_trigger == '0':
                            dict_of_vmnames_defgw[name] = 'NONE'

                # =============== L2 MULTISWITCH: ПОДМЕНА L1 -> L2 ===============
                # Все проверки ниже (Networks, шлюзы, дубли, домены) работают по
                # bridges. При активной L2-подсказке заменяем физическую картину
                # (точечные линки "узел-порт свитча") VLAN-доменами задуманной
                # топологии — дальше базовая логика идёт без изменений.
                if l2res:
                    try:
                        bridges, l2dom_errs, router_int_result = build_l2_domains(l2res, bridges, dict_of_name_and_intname, dict_of_subints)
                        errors['errors_noty'].extend(l2dom_errs)
                        # Изоляция сети от роутера не покрывается базовыми
                        # проверками (особенно при подсказке без номеров) —
                        # отдельный пункт с баллами
                        if router_int_result:
                            add_check('vlan_router_int', router_int_result[0], router_int_result[1])
                        answer['l2_domains'] = str(bridges)
                        answer['l2_subints'] = str(dict_of_subints)
                    except Exception:
                        log('build_l2_domains err', traceback.format_exc())
                # =============== L2 MULTISWITCH: ПОДМЕНА L1 -> L2 END ===============

                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'linux':
                        tmpdefroute = 0
                        for routes in dict_of_name_fullcmd[name]['IPROUTE']:
                            if 'default via' in routes:
                                tmpdefroute = 1
                                dict_of_vmnames_defgw[name] = routes.split()[2]
                                break
                        if tmpdefroute == 0:
                            dict_of_vmnames_defgw[name] = 'NONE'
                    if dict_of_name_and_ostype[name] == 'mikrotik':
                        #routeros_defgw = run_on_routeros('/ip route print', port)
                        if dict_of_name_routeros_script[name]['DEFGW']:
                            routeros_route_table = dict_of_name_routeros_script[name]['DEFGW']
                            for line in dict_of_name_routeros_script[name]['DEFGW']:
                                if '0.0.0.0/0' in line:
                                    dict_of_vmnames_defgw[name] = line.split()[3]
                                    break
                                dict_of_vmnames_defgw[name] = 'NONE'
                        else:
                            routeros_route_table = 'NONE'
                
                tasks = []
                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'linux':
                        tmpdnsclient = 0
                        for dnsclient in dict_of_name_fullcmd[name]['DNSCLI']:
                            if 'nameserver' in dnsclient:
                                if len(dnsclient.split()) != 1:
                                    tmpdnsclient = 1
                                    dict_of_vmnames_dnssrv[name] = dnsclient.split()[1]
                        if tmpdnsclient == 0:
                            dict_of_vmnames_dnssrv[name] = 'NONE'
                    elif dict_of_name_and_ostype[name] == 'mikrotik':
                        if dict_of_name_routeros_script[name]['DNS']:
                            for line in dict_of_name_routeros_script[name]['DNS']:
                                if 'dynamic-servers:' in line or 'servers:' in line:
                                    linelist = line.split(': ')
                                    if len(linelist) == 2:
                                        dict_of_vmnames_dnssrv[name] = linelist[1]
                                    break
                                dict_of_vmnames_dnssrv[name] = 'NONE' 
                                    
                    elif dict_of_name_and_ostype[name] == 'win' or dict_of_name_and_ostype[name] == 'winserver':

                            for line in dict_of_name_fullcmd[name]['DNSCLI']:
                                if 'DNS Servers' in line:
                                    dnssrv = line.split(':')[1].strip()
                                    if dnssrv:
                                        dict_of_vmnames_dnssrv[name] = dnssrv
                                    else:
                                        dict_of_vmnames_dnssrv[name] = "NONE"
                                    break


                
                answer['dict_of_vmnames_hostname'] = dict_of_vmnames_hostname
                answer['dict_of_vmnames_defgw'] = dict_of_vmnames_defgw
                answer['dict_of_vmnames_dnssrv'] = dict_of_vmnames_dnssrv
                answer['dict_of_intnames_ipaddr'] = dict_of_intnames_ipaddr
                dict_of_intnames_ipaddr_for_answer = {}
                for dictkey in dict_of_intnames_ipaddr.keys():
                    tmpname = get_vmname_by_intname(dictkey, dict_of_name_and_intname)
                    if tmpname in dict_of_intnames_ipaddr_for_answer.keys():
                        dict_of_intnames_ipaddr_for_answer[tmpname] = dict_of_intnames_ipaddr_for_answer[tmpname] + ', ' + dict_of_intnames_ipaddr[dictkey]
                    else:
                        dict_of_intnames_ipaddr_for_answer[tmpname] = dict_of_intnames_ipaddr[dictkey]
                answer['dict_of_intnames_ipaddr_for_answer'] = dict_of_intnames_ipaddr_for_answer
                

                log('dict_of_vmnames_hostname', dict_of_vmnames_hostname)
                log('dict_of_vmnames_defgw', dict_of_vmnames_defgw)
                log('dict_of_vmnames_dnssrv', dict_of_vmnames_dnssrv)
                log('dict_of_intnames_ipaddr', dict_of_intnames_ipaddr)
                log('dict_of_name_and_ostype', dict_of_name_and_ostype)
                for intname in dict_of_intnames_ipaddr:
                    if dict_of_intnames_ipaddr[intname] == 'DOWN':
                        dict_of_intnames_network[intname] = 'DOWN'
                    elif dict_of_intnames_ipaddr[intname] == 'NONE':
                        dict_of_intnames_network[intname] = 'NONE'
                    elif dict_of_intnames_ipaddr[intname] == 'MULTI':
                        dict_of_intnames_network[intname] = 'MULTI'
                    else:
                        # if get_network_address(dict_of_intnames_ipaddr[intname]) == dict_of_intnames_ipaddr[intname]:
                        #     dict_of_intnames_ipaddr[intname] = 'BAD'
                        # else:
                            dict_of_intnames_network[intname] = get_network_address(dict_of_intnames_ipaddr[intname])
                answer['dict_of_intnames_network'] = dict_of_intnames_network
                log('dict_of_intnames_network', dict_of_intnames_network)

                for vmname in dict_of_name_and_intname:
                    i = 0
                    for intname in dict_of_name_and_intname[vmname]:
                        i = i+1
                    if i != 1 and dict_of_name_and_ostype[vmname] == 'linux': 
                        list_of_routers.append(vmname)
                    if i != 1 and  dict_of_name_and_ostype[vmname] == 'mikrotik':
                        list_of_routers.append(vmname)
                answer["list_of_routers"] = list_of_routers
                log('list_of_routers', list_of_routers)


                for bridge in bridges:
                    tmplist = []
                    for intname in bridges[bridge]:
                    
                        if 'vunl' in intname:
                            tmplist.append(get_vmname_by_intname(intname, dict_of_name_and_intname))
                        else:
                            tmplist.append('internet')

                    dict_of_bridges_vmnames[bridge] = tmplist
                answer["dict_of_bridges_vmnames"] = dict_of_bridges_vmnames
                log('dict_of_bridges_vmnames', dict_of_bridges_vmnames)

                for router in list_of_routers:
                    tmplist = []
                    for intname in dict_of_name_and_intname[router]:
                        tmplist.append(dict_of_intnames_ipaddr[intname])
                    dict_of_routers_address[router] = tmplist
                answer["dict_of_routers_address"] = dict_of_routers_address
                log('dict_of_routers_address', dict_of_routers_address)

                for net in dict_of_intnames_network.values():
                    if net not in list_of_networks and net != "NONE":
                        list_of_networks.append(net)
                answer["list_of_networks"] = list_of_networks
                log('list_of_networks', list_of_networks)

                ########## BASE CHECKS
                ##########
                print('BASE CHECKS_______________________________')
            
                #### hostname
                chk_count = len(dict_of_vmnames_hostname)
                err_count = 0
                err_list = []
                for vmname in dict_of_vmnames_hostname:
                    if '.' in dict_of_vmnames_hostname[vmname].upper():
                        if vmname.upper() not in dict_of_vmnames_hostname[vmname].upper():
                            errors["hostnames"] = vmname
                            err_list.append(vmname)
                            err_count = err_count + 1
                    else:
                        if vmname.upper() != dict_of_vmnames_hostname[vmname].upper():
                            errors["hostnames"] = vmname
                            err_list.append(vmname)
                            err_count = err_count + 1
                good_count = chk_count - err_count
                add_check('Hostnames', good_count, chk_count)
                if err_count != 0:
                    errors['errors_noty'].append(f'Похоже имеются проблемы с именами на узлах: {err_list}')

                #### ip addresses
                ip_autoconf_pattern = r"169\.254\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/16"
                chk_count = len(dict_of_intnames_ipaddr)
                err_count = 0
                tmp_err_ip = []
                tmp_err_mask = []
                tmp_err_autoconf = []
                for intname in dict_of_intnames_ipaddr:
                    if 'gre0' in intname or 'gretap' in intname or 'erspan' in intname:
                        continue
                    vmname = get_vmname_by_intname(intname, dict_of_name_and_intname)
                    v = dict_of_intnames_ipaddr[intname]
                    bad = False
                    if v == 'NONE' or v == 'MULTI' or v == 'DOWN':
                        errors["ipaddrs"] = vmname
                        tmp_err_ip.append(vmname)
                        bad = True
                    if '/0' in v or '/32' in v or '/8' in v:
                        tmp_err_mask.append(vmname)
                        bad = True
                    if re.match(ip_autoconf_pattern, v):
                        tmp_err_autoconf.append(vmname)
                        bad = True
                    # Один проблемный интерфейс = -1 элемент (не суммируем 30 за каждый признак)
                    if bad:
                        err_count = err_count + 1
                if tmp_err_ip:
                    errors['errors_noty'].append(f'Имеются проблемы с адресами на узлах: {tmp_err_ip}')
                if tmp_err_mask:
                    errors['errors_noty'].append(f'Похоже имеются проблемы с маской на узлах: {tmp_err_mask}')
                if tmp_err_autoconf:
                    errors['errors_noty'].append(f'Похоже dhcp клиент не получил ответа и назначил адреса из сети 169.254.0.0/16: {tmp_err_autoconf}')
                good_count = chk_count - err_count
                add_check('Ip Addresses', good_count, chk_count)

                #### networks
                chk_count = len(bridges) - 1
                err_count = 0

                for bridge in bridges:
                    if bridge != 'pnet0':
                        nets_to_check = []
                        intnames_list = []
                        for intname in bridges[bridge]:
                            int_ostype = int_of_ostype(intname, dict_of_name_and_intname, dict_of_name_and_ostype)
                            # if int_ostype != 'viosl2' and dict_of_intnames_ipaddr[intname] != 'NONE' and dict_of_intnames_ipaddr[intname] != 'MULTI' and dict_of_intnames_ipaddr[intname] != 'DOWN':
                            if int_ostype not in ('viosl2', 'iol') and intname in dict_of_intnames_ipaddr and dict_of_intnames_ipaddr[intname] != 'NONE' and dict_of_intnames_ipaddr[intname] != 'MULTI' and dict_of_intnames_ipaddr[intname] != 'DOWN':
                                nets_to_check.append(dict_of_intnames_ipaddr[intname])
                                intnames_list.append(intname)
                        if nets_to_check:
                            if not check_same_network(nets_to_check):
                                bad_nets = []
                                for intname in intnames_list:
                                    for vmname in dict_of_name_and_intname:
                                        for intname2 in dict_of_name_and_intname[vmname]:
                                            if intname == intname2:
                                                bad_nets.append(vmname)
                                # Мост с разными сетями = -1 элемент
                                err_count = err_count + 1
                                errors["multinet_in_l2domain"] = bad_nets
                                errors['errors_noty'].append(f'Разные сети в одном широковещательном домене: {bad_nets}')

                        else:
                            errors["crit"] = "err"
                good_count = chk_count - err_count
                add_check('Networks', good_count, chk_count)

                #### Duplicate IP
                chk_count = 1
                err_count = 0
                dup_ips_intnames = check_duplicates(dict_of_intnames_ipaddr)
                if dup_ips_intnames:
                    dup_vmnames = []
                    for intname in dup_ips_intnames:
                        dup_vmnames.append(get_vmname_by_intname(intname, dict_of_name_and_intname))
                    # Бинарная проверка: есть дубликаты или нет
                    err_count = 1
                    errors["Имеются повторяющиеся адреса"] = dup_vmnames
                    errors['errors_noty'].append(f'Имеются повторяющиеся адреса: {dup_vmnames}')
                    #return 'Имеются повторяющиеся адреса', dup_vmnames
                good_count = chk_count - err_count
                add_check('nodup_ipaddr', good_count, chk_count)

                #### IP is private
                chk_count = 1
                err_count = 0
                for intname in dict_of_intnames_ipaddr:
                    if dict_of_intnames_ipaddr[intname] != 'NONE' and dict_of_intnames_ipaddr[intname] != 'MULTI' and dict_of_intnames_ipaddr[intname] != 'DOWN' and get_vmname_by_intname(intname, dict_of_name_and_intname) != 'ISP':
                        if not is_private_network(dict_of_intnames_ipaddr[intname]):
                            #return 'Используются не приватные сети', get_vmname_by_intname(intname, dict_of_name_and_intname)
                            errors["Используются не приватные сети" + get_vmname_by_intname(intname, dict_of_name_and_intname)] = 'err'
                            err_count = 1
                    
                    # else:
                    #     err_count = err_count + 1
                good_count = chk_count - err_count
                add_check('IP is private', good_count, chk_count)

                #### Def gw is present
                chk_count = len(list_of_vmnames)
                err_count = 0
                err_list = []
                if len(bridges['pnet0']) != 1:
                    tmplist = []
                    for vmname in dict_of_vmnames_defgw:
                        if dict_of_vmnames_defgw[vmname] == 'NONE':
                            tmplist.append(vmname)
                            err_count = err_count + 1
                            err_list.append(vmname)
                    if tmplist:
                        errors['Нет шлюза по умолчанию'] = tmplist
                    good_count = chk_count - err_count
                    add_check('Default gw present', good_count, chk_count)
                    if err_count != 0:
                        errors['errors_noty'].append(f'Нет default gateway: {err_list}')
                else:
                    add_check('Default gw present', 0, 0)
                #### Def gw is good
                print('start def gw is good')
                chk_count = len(list_of_vmnames)
                err_count = 0
                err_list = []
                if len(bridges['pnet0']) != 1:
                #if "pnet0" in bridges:
                    # Множество реальных адресов интерфейсов (по хост-части, без префикса).
                    # Берём и из dict_of_intnames_ipaddr, и из realaddr — так шлюз находится,
                    # даже если интерфейс схлопнут в MULTI (иначе раздел «протекал» бы в ноль).
                    valid_gw_addrs = set()
                    for a in list(dict_of_intnames_ipaddr.values()) + list(dict_of_intnames_realaddr.values()):
                        if a and a not in ('NONE', 'MULTI', 'DOWN'):
                            valid_gw_addrs.add(a.split('/')[0])
                    for vmname in dict_of_vmnames_defgw:
                        gw = dict_of_vmnames_defgw[vmname]
                        if gw.startswith('10.254.') or (gw != 'NONE' and gw.split('/')[0] in valid_gw_addrs):
                            trigger = 1
                        else:
                            trigger = 0
                        if trigger == 0:
                            # return 'Не верный шлюз по умолчанию', vmname
                            errors['Не верный шлюз по умолчанию ' + vmname] = 'err'
                            errors['errors_noty'].append(f'Не верный шлюз по умолчанию: {vmname}')
                            err_list.append(vmname)
                            err_count = err_count + 1
                    good_count = chk_count - err_count
                    if err_count != 0:
                        errors['errors_noty'].append(f'Есть проблемы с default gateway: {err_list}')
                    add_check('Default gw good', good_count, chk_count)
                else:
                    add_check('Default gw good', 0, 0)

                #### Networ overlaps
                network_list = []
                for network in dict_of_intnames_network.values():
                    if network != "NONE" and network != "DOWN" and network != "MULTI":
                        network_list.append(network)
                network_list = list(dict.fromkeys(network_list))
                if check_network_overlap(network_list):
                    #return "Есть пересекающиеся сети", network_list
                    errors["Есть пересекающиеся сети"] = network_list
                    errors['errors_noty'].append(f'Есть пересекающиеся сети: {network_list}')
                    
                #### IP forwardin is enabled on routers
                chk_count = len(list_of_routers)
                err_count = 0
                tasks = []
                for name in list_of_routers:
                    if dict_of_name_and_ostype[name] == 'linux':
                        for forwarding in dict_of_name_fullcmd[name]['FORWARDING']:
                            if 'net.ipv4.ip_forward' in forwarding and forwarding.split()[2] == '0':
                                errors['errors_noty'].append(f'Форвардинг пакетов не включен на каком-то из маршрутизаторов')
                                errors['Форвардинг пакетов не включен на каком-то из маршрутизаторов'] = 'err'
                                err_count = err_count + 1

                good_count = chk_count - err_count
                add_check('Forwarding_enable', good_count, chk_count)

                #### IP forwardin is disaabled on linux clients
                # Штрафная проверка: forwarding на клиенте по умолчанию выключен,
                # поэтому корректное состояние баллов не даёт, а включённый — штрафуется.
                bad_fwd = 0
                tasks = []
                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'linux' and name not in list_of_routers:
                        for forwarding in dict_of_name_fullcmd[name]['FORWARDING']:
                            if 'net.ipv4.ip_forward' in forwarding and forwarding.split()[2] != '0':
                                bad_fwd = bad_fwd + 1
                                errors['errors_noty'].append(f'Форвардинг пакетов включен на каком-то из клиентов')
                                errors['Форвардинг пакетов включен на каком-то из клиентов'] = 'err'

                add_penalty('Forwarding_disable', bad_fwd)

                #### DNS servers
                print('start def DNS')
                chk_count = len(dict_of_vmnames_dnssrv)
                err_count = 0
                tmplist = []
                for vmname in dict_of_vmnames_dnssrv:
                    if dict_of_vmnames_dnssrv[vmname] == 'NONE':
                        err_count = err_count + 1
                        tmplist.append(vmname)
                if tmplist:
                    errors['Не указан dns сервер'] = tmplist
                    errors['errors_noty'].append(f'Не указан dns сервер: {tmplist}')
                good_count = chk_count - err_count
                add_check('dnsclient_ip_addr', good_count, chk_count)

                #### SNAT ######
                chk_count = len(list_of_routers) + 1 * len(list_of_routers)
                err_count = 0
                masq = 0
                tasks = []
                errors['nftables'] = []
                errors['SNAT'] = []

                for router in list_of_routers:
                    extrouter = 0
                    for tmpint in dict_of_name_and_intname[router]:
                        if tmpint in bridges['pnet0']:
                            extrouter =1
                    if dict_of_name_and_ostype[router] == 'linux' and extrouter == 1:
                        tmp = 0
                        for nftservice in dict_of_name_fullcmd[router]['NFTSERVICE']:
                            if ' disabled;' in nftservice:
                                errors['nftables'].append(router + ': service disabled')
                                err_count = err_count + 1
                            elif 'Active: failed' in nftservice:
                                errors['nftables'].append(router + ': service failed')
                                err_count = err_count + 1
                            elif 'Active: inactive' in nftservice:
                                errors['nftables'].append(router + ': service stopped')
                                err_count = err_count + 1
                            # if 'masquerade' in res[2]:
                            #     errors['SNAT'].append(router + ': MASQ not enabled')
                            #     err_count = err_count + 1
                        for nftrules in dict_of_name_fullcmd[router]['NFTRULES']:
                            # for nftrule in nftrules:
                            if 'masquerade' in nftrules:
                                tmp = 1
                        if tmp == 0:
                            err_count = err_count + 1
                            errors['errors_noty'].append(f'Не настроен маскарад: {router}')
                        good_count = chk_count - err_count
                        add_check('snat_nftables', good_count, chk_count)
                        if errors['SNAT']:
                            errors['errors_noty'].append(f'Не настроен маскарад: {errors["SNAT"]}')
                        if errors['nftables']:
                            errors['errors_noty'].append(f'Проблемы с nftables: {errors["nftables"]}')

                    if dict_of_name_and_ostype[router] == 'mikrotik' and extrouter == 1:
                        #routeros_snat = run_on_routeros('/ip firewall nat print', port)
                        
                        if dict_of_name_routeros_script[router]['FWNAT']:
                            for line in dict_of_name_routeros_script[router]['FWNAT']:
                                if 'action=masquerade' in line and dict_routeros_ints_bymac[next(iter(dict_routeros_ints_bymac))]:
                                    masq = 1
                        if masq == 0:   
                            errors['SNAT'].append(router)
                            err_count = err_count + 1


                ps_script = 'Write-Host "DHCPSCOPE =START="; [Threading.Thread]::CurrentThread.CurrentUICulture = "en-US"; powershell Get-DhcpServerv4Scope 2>$null; Write-Host "DNSZONE =START="; Get-DnsServerZone; Write-Host "ADDC =START="; Get-ADDomainController; Write-Host "DNSFWD =START="; Get-DnsServerForwarder'
                #ps_script = 'Write-Host "DNSZONE =START="; Get-DnsServerZone; Write-Host "ADDC =START="; Get-ADDomainController'
                ps_script = 'Write-Host "DHCPSCOPE =START="; [Threading.Thread]::CurrentThread.CurrentUICulture = "en-US"; powershell Get-DhcpServerv4Scope 2>$null; Write-Host "DNSZONE =START="; Get-DnsServerZone; Write-Host "DNSFWD =START="; Get-DnsServerForwarder; Write-Host "ADDC =START="; chcp 65001; nltest /domain_trusts'
                # ps_script = 'hostname'

                ##### WINDOWS SERVICE
                tasks = []
                winserver_is_present = 0
                chk_count = 0
                good_count = 0
                for name in list_of_vmnames:
                    WinDCisTrue = False
                    
                    if dict_of_name_and_ostype[name] == 'winserver':
                        chk_count = chk_count + 3
                        winserver_is_present = 1
                        # print('start def WIN services')
                        #task = asyncio.ensure_future(execute_command('Get-ADDomainController', 'powershell', dict_of_name_and_path[name], name, 'getDC'))
                        task = asyncio.ensure_future(execute_command(ps_script, 'powershell', dict_of_name_and_path[name], name, 'getDC'))
                        tasks.append(task)
                        getDcOut = await asyncio.gather(*tasks)
                        answer['getDcOut_raw'] = getDcOut

                        script_OUT = {}
                        current_section = None
                        for outline in getDcOut[0][2].splitlines():
                            if "=START=" in outline:
                                # Если начинается новая секция и предыдущая секция не пуста, обновляем current_section
                                if current_section is not None and not script_OUT[current_section]:
                                    script_OUT[current_section].append("NONE")
                                current_section = outline.split(" ")[0].strip("=")
                                script_OUT[current_section] = []
                            elif current_section is not None:
                                script_OUT[current_section].append(outline.strip())
                        dict_of_name_winservers_script[name] = script_OUT
                    

                        for dcout in dict_of_name_winservers_script[name]['ADDC']:
                            if '0:' in dcout:
                                answer['WinDomain'] = dcout.split()[2].strip()
                                WinDCisTrue = True
                                good_count = good_count + 3
                        if not WinDCisTrue:
                            errors['errors_noty'].append(f'Котроллер домена не развернут: {name}')
                            answer['WinDomain'] = 'NODOMAINWINSRVHOST'
                    answer['dict_of_name_winservers_script'] = dict_of_name_winservers_script
                    add_check('Win Domain', good_count, chk_count)
                    

                ######### DOMAIN CLIENTS CHECK
                tasks = []
                chk_count = 0
                err_count = 0
                join_domain_err = []
                if winserver_is_present == 1:
                    for name in list_of_vmnames:
                        if dict_of_name_and_ostype[name] == 'win':
                            chk_count = chk_count + 1
                            task = asyncio.ensure_future(execute_command('chcp 65001 & nltest /domain_trusts', 'windows', dict_of_name_and_path[name], name, 'joindomain'))  
                            tasks.append(task)
                    list_domain_join = await asyncio.gather(*tasks)
                    answer['list_domain_join'] = list_domain_join
                    for line in list_domain_join:
                        if answer['WinDomain'] not in line[2]:
                            join_domain_err.append(line[0])
                            err_count = err_count + 1
                if join_domain_err:
                    errors['errors_noty'].append(f'Есть не введенные в домен узлы: {join_domain_err}')
                good_count = chk_count - err_count
                add_check('joined_to_domain', good_count, chk_count)
                answer['dict_of_vmnames_hostname'] = dict_of_vmnames_hostname
                
                ########## MULTI ROUTES
                
                if len(list_of_routers) > 1 and len(bridges['pnet0']) != 1:
                    # Шкала — количество сетей: -1 за каждую сеть без корректного маршрута
                    chk_count = len(list_of_networks)
                    err_count = 0
                    extrouter = dict_of_bridges_vmnames['pnet0'][1]
                    tmp_routes = []
                    if dict_of_name_and_ostype[extrouter] == 'linux':
                        for route in dict_of_name_fullcmd[extrouter]['IPROUTE']:
                            if 'default' not in route:
                                if 'proto kernel scope' in route:
                                    tmp_routes.append(route.split(' ')[0] + ':DIRECT')
                                elif 'via' in route:
                                    tmp_routes.append(route.split(' ')[0] + ':' + route.split(' ')[2])
                        answer['routes_lists'] = tmp_routes
                        if len(tmp_routes) != len(list_of_networks) and not gre_present:
                            # print(gre_present)
                            errors['errors_noty'].append('Количество маршрутов не совпадает с количеством сетей')
                            err_count = chk_count
                        else:
                            for network in list_of_networks:
                                tmp = 0
                                for route in tmp_routes:
                                    if network in route:
                                        if route.split(":")[1] == 'DIRECT':
                                            tmp = 1
                                        else:
                                            for router in list_of_routers:
                                                if router != extrouter:
                                                    # print('AAAAAAAAAAA', dict_of_name_fullcmd)
                                                    if dict_of_name_and_ostype[router] != 'mikrotik':
                                                        if route.split(":")[0] in str(dict_of_name_fullcmd[router]['IPROUTE']) and route.split(":")[1] in str(dict_of_name_fullcmd[router]['IPROUTE']):
                                                            tmp = 1
                                                    else:
                                                        if route.split(":")[0] in str(dict_of_name_routeros_script[router]['IPROUTE']) and route.split(":")[1] in str(dict_of_name_routeros_script[router]['IPROUTE']):
                                                            tmp = 1
                                if tmp != 1:
                                    errors['errors_noty'].append(f'Что-то не так с роутом до сети {network}')
                                    err_count = err_count + 1
                    good_count = chk_count - err_count
                    add_check('multiroutes', good_count, chk_count)
                else:
                    add_check('multiroutes', 0, 0)



                if 'OSIS_PR1.unl' in lab_path:
                    chk_count = 28
                    err_count = 0
                    name = 'FS'
                    tasks = []
                    answer['df-h'] = []
                    task = asyncio.ensure_future(execute_command("ls -l /mnt/ |grep data && ls -l /mnt/ |grep 5gb && ls -l /mnt/ |grep 9gb && echo OKMOUNTPOINT", 'linux', dict_of_name_and_path[name], name, 'mountpoint'))  
                    tasks.append(task)
                    list_of_mountpoints = await asyncio.gather(*tasks)
                    for result in list_of_mountpoints:
                        if 'OKMOUNTPOINT' not in result[2]:
                            errors['errors_noty'].append(f'Похоже не созданны какие-то mountpoints или имеют имена не по заданию: {name}')
                            err_count = err_count + 3

                    tasks = []
                    task = asyncio.ensure_future(execute_command("df -hT |grep data && df -hT |grep 5gb && df -hT |grep 9gb && echo OKMOUNTED", 'linux', dict_of_name_and_path[name], name, 'mountpoint'))  
                    tasks.append(task)
                    list_of_mountpoints = await asyncio.gather(*tasks)
                    for result in list_of_mountpoints:

                        if 'OKMOUNTED' not in result[2]:
                            errors['errors_noty'].append(f'Похоже какието разделы не смонтированны: {name}')
                            err_count = err_count + 3
                        for res in result[2].split('\n'):
                            answer['df-h'].append(res)
                        if answer['df-h'][0] == 'NONE':
                            err_count = err_count + 9
                        else:
                            vdb1 = 0
                            vdc1 = 0
                            vdc2 = 0
                            for res in answer['df-h']:
                                if 'data' in res and 'ext3' in res:
                                    vdb1 = 1
                            for res in answer['df-h']:
                                if '5gb' in res and 'ext4' in res:
                                    vdc1 = 1
                            for res in answer['df-h']:
                                if '9gb' in res and 'ext3' in res:
                                    vdc2 = 1
                            if vdb1 == 0 or vdc1 == 0 or vdc2 == 0:
                                err_count = err_count + 3
                                errors['errors_noty'].append(f'Похоже файловые системы не по заданию: {name}')
                            tasks = []
                            task = asyncio.ensure_future(execute_command("umount -f /mnt/data;umount -f /mnt/5gb;umount -f /mnt/9gb", 'linux', dict_of_name_and_path[name], name, 'mountpoint'))
                            tasks.append(task)
                            list_of_fstab = await asyncio.gather(*tasks)
                            tasks = []
                            task = asyncio.ensure_future(execute_command("mount -a", 'linux', dict_of_name_and_path[name], name, 'mountpoint'))
                            tasks.append(task)
                            list_of_fstab = await asyncio.gather(*tasks)
                            tasks = []
                            task = asyncio.ensure_future(execute_command("df -hT |grep data && df -hT |grep 5gb && df -hT |grep 9gb && echo OKMOUNTED", 'linux', dict_of_name_and_path[name], name, 'mountpoint'))  
                            tasks.append(task)
                            list_of_mountpoints2 = await asyncio.gather(*tasks)
                            for result2 in list_of_mountpoints2:
                                if 'OKMOUNTED' not in result2[2]:
                                    errors['errors_noty'].append(f'Похоже какието проблемы с конфигурацией fstab: {name}')
                                    err_count = err_count + 6
                    keyforchk = '3PkBGcuy1vP4Op1JRSqY2PN2CEetwFMGA6dgHdRbWs1quL/u6A9+blPxJ17xb3HCWPiUhAACAj2m48ptzJ3sdYhu81pcV6TUa65cOJtt3FYcWa+KXnWdbY2eS3UgIYFfvQmjK'

                    name = 'SSHDSRV'
                    tasks = []
                    # answer['keyfile'] = []
                    task = asyncio.ensure_future(execute_command("ls / |grep -c keyfolder && echo FOLDEROK;ls /keyfolder/keyfile && echo FILEOK;cat /keyfolder/keyfile", 'linux', dict_of_name_and_path[name], name, 'key'))  
                    tasks.append(task)
                    list_of_keys = await asyncio.gather(*tasks)
                    for result in list_of_keys:
                        # answer['keyfile'].append(result[2])
                        if 'FOLDEROK' not in result[2]:
                            errors['errors_noty'].append(f'Каталог keyfolder не найден: {name}')
                            err_count = err_count + 2
                        if 'FILEOK' not in result[2]:
                            errors['errors_noty'].append(f'Файл keyfile не найден: {name}')
                            err_count = err_count + 2
                        if keyforchk not in result[2]:
                            errors['errors_noty'].append(f'Содержимое файла keyfile не по заданию: {name}')
                            err_count = err_count + 3
                    
                    tasks = []
                    # answer['keyfile'] = []
                    task = asyncio.ensure_future(execute_command("ls /root/.ssh/authorized_keys && echo KEYSOK", 'linux', dict_of_name_and_path[name], name, 'key'))  
                    tasks.append(task)
                    list_of_keys = await asyncio.gather(*tasks)
                    for result in list_of_keys:
                        # answer['keyfile'].append(result[2])
                        if 'KEYSOK' not in result[2]:
                            errors['errors_noty'].append(f'Похоже аутентификация по ключам не настроенна: {name}')
                            err_count = err_count + 3
                        

                    good_count = chk_count - err_count
                    add_check('special', good_count, chk_count)



    # #### Multi routers
    #             tasks = []
    #             tmplist = []
    #             bad_vmname = []
    #             badgw_vmname = []
    #             defgw_vmname = []
    #             route_count = []
    #             if len(bridges['pnet0']) != 1:
    #                 for router in list_of_routers:
    #                     if dict_of_name_and_ostype[router] == 'linux':
    #                         if router in dict_of_bridges_vmnames['pnet0']:
    #                             task = asyncio.ensure_future(execute_command('ip r |grep -v default', 'linux', dict_of_name_and_path[router], router, 'NULL'))
    #                             tasks.append(task)
    #                 result = await asyncio.gather(*tasks)
    #                 for res in result:
    #                     for route_line in res[2].split('\n'):
    #                         tmplist.append(route_line.split(' ')[0])
    #                     if len(list_of_networks) != len(tmplist):
    #                         errors['Не верное количество маршрутов'] = router
    #                     for net in list_of_networks:
    #                         if net not in tmplist:
    #                             bad_vmname.append(res[0])
    #                             #errors['Нет некоторых маршрутов'] = net
    #                     ###нужно добавить проверку шлюзов у маршрутов

    #             else:
    #                 for name in list_of_vmnames:
    #                     if dict_of_name_and_ostype[name] == 'linux':
    #                             task = asyncio.ensure_future(execute_command('ip r |grep -c default; ip r', 'linux', dict_of_name_and_path[name], name, 'NULL'))
    #                             tasks.append(task)
    #                     if dict_of_name_and_ostype[name] == 'win':
    #                             task = asyncio.ensure_future(execute_command('chcp 65001 & netsh interface ipv4 show route', 'windows', dict_of_name_and_path[name], name, 'NULL'))
    #                             tasks.append(task)
    #                 result = await asyncio.gather(*tasks)
    #                 for res in result:
    #                     if res[3] == 'windows':
    #                         wincmd_lines = res[2].split('\n')
    #                         tmpwinlist = []
    #                         for line in wincmd_lines:
    #                             if '/32' not in line and 'Loopback' not in line and '224.0.0.0' not in line and ('Manual' in line or 'System' in line):
    #                                 tmpwinlist.append(line.split()[3])
    #                         if len(list_of_networks) != len(tmpwinlist):
    #                             route_count.append(res[0])
    #                         if '0.0.0.0/0' in tmpwinlist:
    #                             defgw_vmname.append(res[0])    
    #                         for net in list_of_networks:
    #                             if net not in tmpwinlist:
    #                                 bad_vmname.append(res[0])
    #                         tmpwinlist = []
    #                         for line in wincmd_lines:
    #                             if '/32' not in line and 'Loopback' not in line and '224.0.0.0' not in line and ('Manual' in line or 'System' in line):
    #                                 tmpwinlist.append(line.split()[5])
    #                         for route_gw in tmpwinlist:
    #                             print(route_gw)
    #                             if route_gw != "Ethernet":
    #                                 if route_gw not in str(dict_of_routers_address):
    #                                     badgw_vmname.append(res[0])

    #                     elif res[3] == 'linux':
    #                         lincmd_lines = res[2].split('\n')
    #                         tmplinlist = []
    #                         if lincmd_lines[0] == '1':
    #                             defgw_vmname.append(res[0])
    #                         lincmd_lines.pop(0)
    #                         for line in lincmd_lines:
    #                             tmplinlist.append(line.split()[0])
    #                         print(tmplinlist)
    #                         if len(list_of_networks) != len(tmplinlist):
    #                             route_count.append(res[0])
    #                         for line in lincmd_lines:
    #                             tmplinlist.append(line.split()[2])
    #                         ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    #                         for route_gw in tmplinlist:
    #                             if re.match(ip_pattern, route_gw):
    #                                 if route_gw not in str(dict_of_routers_address):
    #                                     badgw_vmname.append(res[0])
    #                         for net in list_of_networks:
    #                             if net not in tmplinlist:
    #                                 bad_vmname.append(res[0])
                
    #             if bad_vmname:        
    #                 errors['Нет некоторых маршрутов'] = list(dict.fromkeys(bad_vmname))
    #             if badgw_vmname:
    #                 errors['Не верный шлюз у маршрута'] = list(dict.fromkeys(badgw_vmname))
    #             if defgw_vmname:
    #                 errors['Используется маршрут по умолчанию'] = defgw_vmname
    #             if route_count:
    #                 errors['Не верное количество маршрутов'] = route_count


            else:
                log('err', 'Не все ноды запущены или запущены лишние в другой лабе')
                answer['errorinfo'] = f'Не все ноды запущены или запущены лишние в другой лабе. {dict_of_vmname_and_uid}'
                forweb['lab_path'] = lab_path.replace('/opt/unetlab/labs', '')
                answer['status'] = 'warn'
        else:
            if lab == 'moreone':
                answer['errorinfo'] = f'Ошибка, перезайдите в лабу'
                forweb['lab_path'] = 'Ошибка, перезайдите в лабу'
                answer['status'] = 'warn'
            else:
                answer['errorinfo'] = 'Нет открытой лабы'
                forweb['lab_path'] = 'Нет открытой лабы'
                answer['status'] = 'warn'

        forwebresult = {}
        forFileResult = {}
        tmpdict = {}
        tmpdict['clientip'] = str(clientip)
        if answer['status'] != 'warn':
            answer['status'] = '200'

        # Единый подсчёт итога: сумма баллов проверок минус штрафы (штрафы в max не входят).
        checks_score = sum(c['score'] for c in checks.values())
        max_score = sum(c['max'] for c in checks.values())
        penalties_total = sum(p['points'] for p in penalties.values())
        score = max(0, checks_score - penalties_total)
        percent = (score / max_score * 100) if max_score else 0
        grade = grade_from_percent(percent)
        # Сдано начиная с оценки 3
        lab_done_flag = 1 if (max_score and grade >= 3) else 0
        forweb['lab_done'] = 'yes' if lab_done_flag else 'no'

        forwebresult.update(tmpdict)
        forwebresult.update(answer)
        forwebresult.update(errors)
        forwebresult.update(forweb)
        forFileResult.update(forwebresult)
        os.remove('/tmp/chk.lock')

        # Снимок собранной диагностики для debug_json — ДО pop() ниже.
        collected = {k: forFileResult[k] for k in COLLECTED_KEYS if k in forFileResult}

        forFileResult.pop('dict_of_name_fullcmd', None)
        forFileResult.pop('dbg', None)
        forFileResult.pop('specout', None)
        forFileResult.pop('dict_of_vmname_and_uid', None)
        forFileResult.pop('dict_of_name_and_intname', None)
        forFileResult.pop('dict_of_name_and_path', None)
        forFileResult.pop('name_ostype', None)
        forFileResult.pop('dict_of_intnames_ipaddr', None)
        forFileResult.pop('dict_of_bridges_vmnames', None)
        forFileResult.pop('dict_of_name_cisco_script', None)
        forFileResult.pop('list_of_vmnames', None)
        forFileResult.pop('list_of_intname', None)
        forFileResult.pop('dict_of_name_routeros_script', None)
        forFileResult.pop('dict_of_name_winservers_script', None)
        forFileResult.pop('dict_of_intnames_network', None)
        forFileResult.pop('bridges', None)
        forFileResult.pop('mikrotik_raw_output', None)
        # Результаты теперь в SQLite (см. save_run ниже); forFileResult идёт в debug_json.
        print('start def final return')
        
        selected_names = ["lab_path", "status", "username", "time", "errors_noty", "errorinfo"]
    
            
        # Подстрока для поиска в именах
        substring = " / "

        # Создаем новый словарь, включающий элементы, удовлетворяющие обоим условиям
        selected_students = {name: forFileResult[name] 
                            for name in forFileResult 
                            if name in selected_names}        
        if max_score != 0:
            selected_students['score'] = f"{score} / {max_score}"
            selected_students['Оценка'] = grade

        # Сохраняем прогон в SQLite (только реально проверенные лабы, status 200)
        if answer['status'] == '200':
            run = {
                'ts': formatted_time,
                'username': username,
                'clientip': str(clientip),
                'lab_path': answer.get('lab_path', forweb.get('lab_path', '')),
                'status': answer['status'],
                'score': score,
                'max_score': max_score,
                'percent': round(percent, 2),
                'grade': grade if max_score else None,
                'lab_done': lab_done_flag,
                'errors_json': json.dumps(errors['errors_noty'], ensure_ascii=False),
                'errorinfo': answer.get('errorinfo'),
                'debug_json': json.dumps(collected, ensure_ascii=False),
                'penalties_json': json.dumps(penalties, ensure_ascii=False),
            }
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, save_run, run, checks)
            except Exception as e:
                log('save_run err', e)

        # Возврат: админам (и по ?fmt=json) — JSON для дебага, студенту — UI.
        if username in admin_list:
            return selected_students, forwebresult
        if fmt == 'json':
            return selected_students

        notice = None
        if answer['status'] != '200':
            notice = answer.get('errorinfo') or forweb.get('lab_path')
        return await render_dashboard(request, notice=notice, status=answer['status'],
                                      current_lab=answer.get('lab_path'))


    except Exception:
        os.remove('/tmp/chk.lock')
        error_traceback = traceback.format_exc()
        log('Внутренняя ошибка скрипта:', error_traceback)
        answer['errorinfo'] = 'internal_err ' + error_traceback
        answer['username'] = username
        answer['time'] = formatted_time
        answer['status'] = 'err'
        forwebresult = {}
        forwebresult.update(answer)
        return forwebresult 
        #return "Внутренняя ошибка скрипта", error_traceback

if not no_run:
    prestart()
print('END')

