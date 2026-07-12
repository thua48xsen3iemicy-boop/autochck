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
                match = re.search(r'\suuid="([a-fA-F0-9\-]+)"\s', line)
                if match:
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

def start_bridge():

    bridges = parse_brctl_show()
    log('bridges:', bridges)
    #print('bridges', bridges)
    list_of_vmid = []
    list_of_intname= []
    dict_of_name_and_intname = {}
    dict_of_name_and_path = {}
    list_of_vmnames = []

    orphan_ports = []
    cleaned_bridges = {}

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
                # У tap-интерфейса нет процесса qemu — осиротевший мост чужой/остановленной лабы
                orphan_ports.append(port)
                continue

            vmname, vmpath, *_ = result
            cleaned_ports.append(port)
            list_of_intname.append(port)
            list_of_vmid.append(vmid[0])
            list_of_vmnames.append(vmname)
            if vmname in dict_of_name_and_intname:
                dict_of_name_and_intname[vmname] = dict_of_name_and_intname[vmname] + ' ' + port
            else:
                dict_of_name_and_intname[vmname] = port

            dict_of_name_and_path[vmname] = vmpath

        # Мост оставляем, только если в нём остались валидные порты.
        # pnet0 при этом сохраняется автоматически — у него легитимно только eth0.
        if cleaned_ports:
            cleaned_bridges[bridge] = cleaned_ports

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
        data = sock.recv(4096)
        # data = read_full_response(sock)
        #log(str(data), socket_path)
        response = json.loads(data.decode("utf-8"))
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
                data = sock.recv(32768)
                log(f'_{socket_path} {command}', data)
                response = json.loads(data.decode("utf-8"))
                #response = json.loads(data)
                # log(f'path: {socket_path}', f'socket data: {response}')
                # Если команда завершилась, вывести результат
                if response.get("return", {}).get("exited", False):
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
MTK_PROMPT = "] >"  # Пример приглашения командной строки MikroTik
CONTIMEOUT = 5  # Таймаут ожидания подключения
EXPTIMEOUT = 3  # Таймаут ожидания ответа


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

def node_login(handler):
    ''' Отправляем пустую строку и ожидаем приглашение к входу '''
    i = -1
    while i == -1:
        #print('wait prompt...')
        try:
            handler.sendline('\r\n')
            i = handler.expect(['Login:', MTK_PROMPT], timeout=CONTIMEOUT)
            #print('PROMPT OK')
        except pexpect.exceptions.TIMEOUT:
            handler.sendline('\r\n')

    if i == 0:
        # Необходимо ввести имя пользователя и пароль
        handler.send(USER_NAME + '+c512wt')
        handler.send('\r\n')
        try:
            handler.expect('Password:', timeout=EXPTIMEOUT)
        except pexpect.exceptions.TIMEOUT:
            print('ERROR: error waiting for "Password:" prompt.')
            #node_quit(handler)
            return False
        handler.sendline(USER_PASS)
        handler.send('\r\n')
        j = handler.expect(['Login:', MTK_PROMPT], timeout=CONTIMEOUT)
        if j == 0:
            return False
        else:
            return True
    elif i == 1:
        # Если сессия уже открыта, отправляем /quit и повторяем процедуру входа
        node_quit(handler)
        return node_login(handler)
    else:
        # Unexpected output
        node_quit(handler)
        handler.send('#unexpected\r\n')
        return False
    #return True

def config_get(handler, cmd):
    ''' Отправляем команду /export и читаем вывод '''
    clear_buffer(handler)
    handler.send(cmd)
    handler.send('\r\n')
    time.sleep(1)

    try:
        handler.expect(
            MTK_PROMPT, timeout=EXPTIMEOUT)
    except pexpect.exceptions.TIMEOUT:
        print('ERROR: error waiting for "end" marker.')
        node_quit(handler)
        return False
    clear_buffer(handler)
    _config = re.sub(r"^.*/export[\r\n]+#", "#", handler.buffer)
    #_config = re.sub(r"^.*/export[\r\n]+#", "#", _config)
    _config = re.sub(r"[\r\n]{2,}.+$", "\r\n\r\n", _config)
    _config = re.sub(r"[\r\n]+", "\r\n", _config)
    node_quit(handler)
    log('routeros get out', _config)
    return _config



def run_on_routeros(cmd, port):
    handler = pexpect.spawnu(f'telnet {IP} {port}', maxread=100000)
    if node_login(handler):
        print("Login successful!")
        out = config_get(handler, cmd)
        return out
    else:
        return False

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


def node_ciscologin(handler):
    # Send an empty line, and wait for the login prompt
    i = -1
    while i == -1:
        try:
            handler.sendline('\r\n')
            i = handler.expect([
                'Username:',
                '\(config',
                '>',
                '#',
                'Would you like to enter the'], timeout = 5)
        except:
            i = -1

    if i == 0:
        # Need to send username and password
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
            # Secret password required
            handler.sendline(cissecret)
            try:
                handler.expect('#', timeout = cisexpctimeout)
            except:
                print('ERROR: error waiting for "#" prompt.')
                node_ciscoquit(handler)
                return False
            return True
        elif j == 1:
            # Nothing to do
            return True
        else:
            # Unexpected output
            node_ciscoquit(handler)
            return False
    elif i == 1:
        # Config mode detected, need to exit
        handler.sendline('end')
        try:
            handler.expect('#', timeout = cisexpctimeout)
        except:
            print('ERROR: error waiting for "#" prompt.')
            node_ciscoquit(handler)
            return False
        return True
    elif i == 2:
        # Need higher privilege
        handler.sendline('enable')
        try:
            j = handler.expect(['Password:', '#'])
        except:
            print('ERROR: error waiting for ["Password:", "#"] prompt.')
            node_ciscoquit(handler)
            return False
        if j == 0:
            # Need do provide secret
            handler.sendline(secret)
            try:
                handler.expect('#', timeout = cisexpctimeout)
            except:
                print('ERROR: error waiting for "#" prompt.')
                node_ciscoquit(handler)
                return False
            return True
        elif j == 1:
            # Nothing to do
            return True
        else:
            # Unexpected output
            node_ciscoquit(handler)
            return False
    elif i == 3:
        # Nothing to do
        return True
    elif i == 4:
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
    if handler.isalive() == True:
        handler.sendline('quit\n')
    handler.close()





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
        node_quit(handler)
        return False

    handler.sendline('echo SHELL ===START===')
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

def run_on_viosl2(handler):
    rc = node_ciscologin(handler)
    if rc != True:
        print('ERROR: failed to login.')
        node_ciscoquit(handler)
        return ['err', 'login']
    config = config_ciscoget(handler)
    if config in [False, None]:
        print('ERROR: failed to retrieve config.')
        node_ciscoquit(handler)
        return ['err', 'output']

    return config

async def execute_command_cisco(handler, name):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, run_on_viosl2, handler)
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

def int_of_ostype(i, d1, d2):
    for key, val in d1.items():
        if isinstance(val, list):
            if i in val:
                exit_key = key
        else:
            if i == val:
                exit_key = key
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

@app.get("/report", response_class=HTMLResponse)
async def read_report(request: Request):
    students = []
    try_history = []
    dbgres = []
    scoresumm = {}
    trysumm = {}
    list_of_results = read_json_file('/data/result.json')
    
    if list_of_results is not None or 'ERRR' not in list_of_results:
        for result in list_of_results:
            if result['lab_path'] != 'Нет открытой лабы':
                dbgres.append(result['lab_path'])
        list_of_labs = list(dict.fromkeys(dbgres))    
        for lab in list_of_labs:
            tmpdict = {}
            for result in list_of_results:
                if result['status'] == '200' and result['lab_path'] == lab:
                    trycount = 0
                    trycountstop = 0
                    score = 0
                    maxscore = 0
                    for line in result.values():
                        if ' / ' in line:
                            line = line.replace(' ', '')
                            sample = line.split('/')
                            score = score + int(sample[0])
                            maxscore = maxscore + int(sample[1])
                            scoresumm['score'] = f'{score}/{maxscore}'
                    try_time = result['time']
                    if result['lab_done'] == 'no':
                        trycount = trycount + 1
                        try_history.append(f'{try_time} : {score}/{maxscore} <br>')
                    tmpdict['try_history'] = try_history
                    result.update(scoresumm)
                    result.update(tmpdict)
                    students.append(result)
    return templates.TemplateResponse("report.html", {"request": request, "students": students})
    #return str(list(dict.fromkeys(dbgres)))

linux_full_cmd = 'echo SSHD ===START;systemctl status ssh|grep -c "Active: active (running)";echo DNSSERVER ===START;systemctl status named|grep -c "Active: active (running)";echo IPADDR ===START;ip a;echo IPROUTE ===START;ip r;echo HOSTNAME ===START;hostname;echo FORWARDING ===START;sysctl net.ipv4.ip_forward;echo DNSCLI ===START;command -v resolvectl >/dev/null && resolvectl status | awk "/Current DNS Server/ {print \"nameserver \" \$NF}" || cat /etc/resolv.conf;echo NFTSERVICE ===START;systemctl status nftables;echo DHCPDINSTALL ===START;dpkg -l |grep -c isc-dhcp-server;echo DHCPDRUN ===START;systemctl status isc-dhcp-server |grep -c "Active: active (running)"'
win_full_cmd = 'chcp 65001 & echo IPADDR ===START & ipconfig & echo IPROUTE ===START & route print -4 & echo HOSTNAME ===START & hostname & echo DNSCLI ===START & netsh interface ipv4 show dns'
#linux_full_cmd = 'echo DNSSERVER ===START;systemctl status named;echo IPADDR ===START;ip a;echo IPROUTE ===START;ip r;echo HOSTNAME ===START;hostname;echo FORWARDING ===START;sysctl net.ipv4.ip_forward;echo DNSCLI ===START;cat /etc/resolv.conf;echo NFTSERVICE ===START;systemctl status nftables;echo DHCPDINSTALL ===START;dpkg -l |grep -c isc-dhcp-server'
linux_nftrules_cmd = 'nft list ruleset'
@app.get("/ping")
async def ping():
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

            return forwebresult
        else:
            print('____________________CREATE LOCK FILE')
            open('/tmp/chk.lock', 'a').close()
        
        answer = {}
        errors = {}
        forweb = {}
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
        cisco_tmps = []
        routeros_tmps = []
        iptasks = []
        output_dict = {}
        dict_of_name_routeros_script = {}
        dict_of_name_cisco_script = {}
        dict_of_name_winservers_script = {}
        dict_of_intnames_ipaddr = {}
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
                } on-error={:put "ERRR";}
                }"""




        log('_________________________________', f'START for {username}')
        if lab != 'moreone' and lab != 'no':
            #return(lab[1])
            lab_path = '/opt/unetlab/labs' + str(lab[1])
            answer['lab_path'] = str(lab[1])
            forweb['lab_path'] = str(lab[1])
            dict_of_name_and_ostype, dict_of_vmname_and_uid = find_uuid_in_file_and_ps(lab_path)
            if dict_of_name_and_ostype != 'count' and dict_of_name_and_ostype != 'multilab':
                answer['name_ostype'] = str(dict_of_name_and_ostype)
                dict_of_name_and_path, list_of_vmnames, list_of_intname, dict_of_name_and_intname, bridges = start_bridge()
                answer['list_of_vmnames'] = str(list_of_vmnames)
                answer['list_of_intname'] = str(list_of_intname)
                answer['dict_of_name_and_intname'] = str(dict_of_name_and_intname)
                answer['dict_of_name_and_path'] = str(dict_of_name_and_path)
                answer['bridges'] = str(bridges)
                answer['dict_of_vmname_and_uid'] = dict_of_vmname_and_uid
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

                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'viosl2':
                        tmpport = dict_of_name_and_path[name]
                        port = int(tmpport.split('/')[1]) + 30000
                        cis_handler = pexpect.spawnu(f'telnet 127.0.0.1 {port}', maxread=100000)
                        cisco_tmp = asyncio.ensure_future(execute_command_cisco(cis_handler, name))
                        cisco_tmps.append(cisco_tmp)                       

                    elif dict_of_name_and_ostype[name] == 'mikrotik':                     
                        tmpport = dict_of_name_and_path[name]
                        port = int(tmpport.split('/')[1]) + 30000
                        handler = pexpect.spawnu(f'telnet {IP} {port}', maxread=100000)
                        routeros_tmp = asyncio.ensure_future(execute_command_routeros(mikrot_script, port, name))
                        routeros_tmps.append(routeros_tmp)
                
                ipresult = await asyncio.gather(*iptasks)
                cisco_results = await asyncio.gather(*cisco_tmps)
                routeros_results = await asyncio.gather(*routeros_tmps)
                answer['mikrotik_raw_output'] = routeros_results
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
                    if routeros_result:

                        dict_routeros_ints_bymac = {}
                        for line in dict_of_name_routeros_script[routeros_result[0]]['EXPORT']:
                            if 'set name=' in line:
                                dict_of_vmnames_hostname[routeros_result[0]] = line.split('=')[1]
                            else:
                                dict_of_vmnames_hostname[routeros_result[0]] = 'NONE'
                        for line in dict_of_name_routeros_script[routeros_result[0]]['INTERFACE']:
                            if mac_address_pattern.search(line.strip()):
                                columns = line.split()
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
                            for key in dict_routeros_ints_bymac.keys():
                                if key == int(int_number):
                                    dict_routeros_ints_bymac[intname] = dict_routeros_ints_bymac.pop(key)
                        unused_ports = []
                        for tmpintname in dict_routeros_ints_bymac.keys():
                            if 'vunl' not in str(tmpintname):
                                unused_ports.append(tmpintname)
                        for tmpintname in unused_ports:
                            dict_routeros_ints_bymac.pop(tmpintname)
                        if dict_routeros_ints_bymac:
                            routeros_conf_addaddr = ''
                            answer['dict_routeros_ints_bymac'] = str(dict_routeros_ints_bymac)
                            if len(dict_of_name_routeros_script[routeros_result[0]]['IPADDR']) != len(dict_routeros_ints_bymac):
                                errors['errors_noty'].append(f'Проблемы на {routeros_result[0]}, количество ip адресов не равно колву интов')
                            
                            for int_name_router in  dict_routeros_ints_bymac.keys():
                                count = sum(dict_routeros_ints_bymac[int_name_router] in s for s in dict_of_name_routeros_script[routeros_result[0]]['IPADDR'])
                                if count == 1:
                                    for addr_line in dict_of_name_routeros_script[routeros_result[0]]['IPADDR']:
                                        if dict_routeros_ints_bymac[int_name_router] in addr_line:
                                            if len(addr_line.split()) == 5:
                                                dict_of_intnames_ipaddr[int_name_router] = addr_line.split()[2]
                                            else:
                                                dict_of_intnames_ipaddr[int_name_router] = addr_line.split()[1]
                                elif count == 0:
                                    dict_of_intnames_ipaddr[int_name_router] = "NONE"
                                elif count > 1:
                                    dict_of_intnames_ipaddr[int_name_router] = "MULTI"
                    else:
                        for intname in dict_of_name_and_intname[routeros_result[0]]:
                            dict_of_intnames_ipaddr[intname] = "NONE"
                        errors['errors_noty'].append(f'Не верный пароль на {routeros_result[0]}') 



                for cisco_result in cisco_results:
                    dict_of_name_cisco_script[cisco_result[0]] = cisco_result[1]

                answer['dict_of_name_cisco_script'] = dict_of_name_cisco_script

                answer['dict_of_vmnames_hostname'] = dict_of_vmnames_hostname        
                answer['dict_of_name_routeros_script'] = dict_of_name_routeros_script


                interface_pattern = r'^\d+: (\w+):'
                mac_pattern = r'link/ether (\S+)'
                state_pattern = r'state (\S+)'
                ipv4_pattern = r'inet (\d+\.\d+\.\d+\.\d+)'
                ipv4_pattern = r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)'
                # ipv4_pattern = r'inet (\d+\.\d+\.\d+\.\d+)(?:/(\d+))?'


                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'linux':
                        gre_present = False
                        linux_ints = {}
                        for line in dict_of_name_fullcmd[name]['IPADDR']:
                            if 'gre' in line:
                                gre_present = True
                            # Поиск имени интерфейса
                            interface_match = re.search(interface_pattern, line)
                            if interface_match:
                                current_interface = interface_match.group(1)
                                linux_ints[current_interface] = {"mac": "", "state": "", "ipv4": []}
                            
                            # Если имя интерфейса найдено, ищем другие данные
                            if current_interface:
                                mac_match = re.search(mac_pattern, line)
                                state_match = re.search(state_pattern, line)
                                ipv4_matches = re.findall(ipv4_pattern, line)

                                if mac_match:
                                    linux_ints[current_interface]["mac"] = mac_match.group(1)
                                if state_match:
                                    linux_ints[current_interface]["state"] = state_match.group(1)
                                if ipv4_matches:
                                    ip_with_mask = []
                                    for ipv4tmp in ipv4_matches:
                                        ip_with_mask.append(ipv4_matches[0][0] + '/' + ipv4_matches[0][1] )
                                    linux_ints[current_interface]["ipv4"].extend(ip_with_mask)
                        dict_of_name_and_ostype['debug'] = linux_ints

                        if name != 'Scan':
                            for intname in dict_of_name_and_intname[name]:
                                # Получаем индекс (0, 1, 2...) из имени вида vunl350_0
                                try:
                                    idx = int(intname.split('_')[1])
                                except (IndexError, ValueError):
                                    idx = 0 

                                # --- ЛОГИКА ФОРМИРОВАНИЯ ИМЕНИ ---
                                if 'pve' in name.lower():
                                    # Для Proxmox: ens3f0, ens3f1...
                                    ens = f'ens3f{idx}'
                                else:
                                    # Стандартная логика: ens3, ens4... (сдвиг +3)
                                    ens = f'ens{idx + 3}'

                                # --- ПРОВЕРКИ СТАТУСА ---
                                # Внимание: Если ens (например, 'ens3f0') нет в linux_ints,
                                # следующая строка вызовет KeyError!
                                if linux_ints[ens]['state'] == 'DOWN':
                                    dict_of_intnames_ipaddr[intname] = "DOWN"
                                elif len(linux_ints[ens]['ipv4']) == 0:
                                    dict_of_intnames_ipaddr[intname] = "NONE"
                                elif len(linux_ints[ens]['ipv4']) > 1 and not gre_present:
                                    dict_of_intnames_ipaddr[intname] = "MULTI"
                                else:
                                    dict_of_intnames_ipaddr[intname] = linux_ints[ens]['ipv4'][0]

                        else:
                            # Блок для Scan
                            for intname in dict_of_name_and_intname[name]:
                                ens = 'eth0'
                                # Тут тоже убрали проверку, если она была не нужна
                                if linux_ints[ens]['state'] == 'DOWN':
                                    dict_of_intnames_ipaddr[intname] = "DOWN"
                                elif len(linux_ints[ens]['ipv4']) == 0:
                                    dict_of_intnames_ipaddr[intname] = "NONE"
                                elif len(linux_ints[ens]['ipv4']) > 1:
                                    dict_of_intnames_ipaddr[intname] = "MULTI"
                                else:
                                    dict_of_intnames_ipaddr[intname] = linux_ints[ens]['ipv4'][0]





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
                            err_count = err_count + 10
                    else:
                        if vmname.upper() != dict_of_vmnames_hostname[vmname].upper():
                            errors["hostnames"] = vmname
                            err_list.append(vmname)
                            err_count = err_count + 10
                good_count = chk_count - err_count
                forweb['Hostnames'] = f'{good_count} / {chk_count}'
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
                    if dict_of_intnames_ipaddr[intname] == 'NONE' or dict_of_intnames_ipaddr[intname] == 'MULTI' or dict_of_intnames_ipaddr[intname] == 'DOWN':
                        errors["ipaddrs"] = vmname
                        tmp_err_ip.append(vmname)
                        err_count = err_count + 30                        
                    if '/0' in dict_of_intnames_ipaddr[intname] or '/32' in dict_of_intnames_ipaddr[intname] or '/8' in dict_of_intnames_ipaddr[intname]:
                        err_count = err_count + 30
                        tmp_err_mask.append(vmname)
                    if re.match(ip_autoconf_pattern, dict_of_intnames_ipaddr[intname]):
                        err_count = err_count + 30
                        tmp_err_autoconf.append(vmname)
                if tmp_err_ip:
                    errors['errors_noty'].append(f'Имеются проблемы с адресами на узлах: {tmp_err_ip}')
                if tmp_err_mask:
                    errors['errors_noty'].append(f'Похоже имеются проблемы с маской на узлах: {tmp_err_mask}')
                if tmp_err_autoconf:
                    errors['errors_noty'].append(f'Похоже dhcp клиент не получил ответа и назначил адреса из сети 169.254.0.0/16: {tmp_err_autoconf}')
                good_count = chk_count - err_count
                forweb['Ip Addresses'] = f'{good_count} / {chk_count}'

                #### networks
                chk_count = len(bridges) - 1
                err_count = 0
                crit_err = 0

                for bridge in bridges:
                    if bridge != 'pnet0':
                        nets_to_check = []
                        intnames_list = []
                        for intname in bridges[bridge]:
                            int_ostype = int_of_ostype(intname, dict_of_name_and_intname, dict_of_name_and_ostype)
                            # if int_ostype != 'viosl2' and dict_of_intnames_ipaddr[intname] != 'NONE' and dict_of_intnames_ipaddr[intname] != 'MULTI' and dict_of_intnames_ipaddr[intname] != 'DOWN':
                            if int_ostype != 'viosl2' and intname in dict_of_intnames_ipaddr and dict_of_intnames_ipaddr[intname] != 'NONE' and dict_of_intnames_ipaddr[intname] != 'MULTI' and dict_of_intnames_ipaddr[intname] != 'DOWN':
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
                                err_count = len(bad_nets) + 30
                                errors["multinet_in_l2domain"] = bad_nets
                                crit_err = len(bad_nets)
                                errors['errors_noty'].append(f'Разные сети в одном широковещательном домене: {bad_nets}')
                        
                        else:
                            errors["crit"] = "err"
                good_count = chk_count - err_count - crit_err
                forweb['Networks'] = f'{good_count} / {chk_count}'

                #### Duplicate IP
                chk_count = 1
                err_count = 0
                dup_ips_intnames = check_duplicates(dict_of_intnames_ipaddr)
                if dup_ips_intnames:
                    dup_vmnames = []
                    for intname in dup_ips_intnames:
                        dup_vmnames.append(get_vmname_by_intname(intname, dict_of_name_and_intname))
                        err_count = err_count + 30
                    errors["Имеются повторяющиеся адреса"] = dup_vmnames
                    errors['errors_noty'].append(f'Имеются повторяющиеся адреса: {dup_vmnames}')
                    #return 'Имеются повторяющиеся адреса', dup_vmnames
                good_count = chk_count - err_count
                forweb['nodup_ipaddr'] = f'{good_count} / {chk_count}'

                #### IP is private
                chk_count = 1
                err_count = 0
                for intname in dict_of_intnames_ipaddr:
                    if dict_of_intnames_ipaddr[intname] != 'NONE' and dict_of_intnames_ipaddr[intname] != 'MULTI' and dict_of_intnames_ipaddr[intname] != 'DOWN' and get_vmname_by_intname(intname, dict_of_name_and_intname) != 'ISP':
                        if not is_private_network(dict_of_intnames_ipaddr[intname]):
                            #return 'Используются не приватные сети', get_vmname_by_intname(intname, dict_of_name_and_intname)
                            errors["Используются не приватные сети" + get_vmname_by_intname(intname, dict_of_name_and_intname)] = 'err'
                            err_count = err_count + 30
                    
                    # else:
                    #     err_count = err_count + 1
                good_count = chk_count - err_count
                forweb['IP is private'] = f'{good_count} / {chk_count}'

                #### Def gw is present
                chk_count = len(list_of_vmnames)
                err_count = 0
                err_list = []
                if len(bridges['pnet0']) != 1:
                    tmplist = []
                    for vmname in dict_of_vmnames_defgw:
                        if dict_of_vmnames_defgw[vmname] == 'NONE':
                            tmplist.append(vmname)
                            err_count = err_count + 30
                            err_list.append(vmname)
                    if tmplist:
                        errors['Нет шлюза по умолчанию'] = tmplist
                    good_count = chk_count - err_count
                    forweb['Default gw present'] = f'{good_count} / {chk_count}'
                    if err_count != 0:
                        errors['errors_noty'].append(f'Нет default gateway: {err_list}')
                else:
                    forweb['Default gw present'] = f'0 / 0'
                #### Def gw is good
                print('start def gw is good')
                chk_count = len(list_of_vmnames)
                err_count = 0
                err_list = []
                if len(bridges['pnet0']) != 1:
                #if "pnet0" in bridges:
                    
                    for vmname in dict_of_vmnames_defgw:
                        trigger = 0
                        for ipaddr in dict_of_intnames_ipaddr.values():
                            if '10.254.' not in dict_of_vmnames_defgw[vmname]:
                                if dict_of_vmnames_defgw[vmname] in ipaddr and dict_of_vmnames_defgw[vmname] != 'NONE':
                                    trigger = 1
                            else:
                                trigger = 1
                        if trigger == 0:
                            # return 'Не верный шлюз по умолчанию', vmname
                            errors['Не верный шлюз по умолчанию ' + vmname] = 'err'
                            errors['errors_noty'].append(f'Не верный шлюз по умолчанию: {vmname}')
                            err_list.append(vmname)
                            err_count = err_count + 30
                    good_count = chk_count - err_count
                    if err_count != 0:
                        errors['errors_noty'].append(f'Есть проблемы с default gateway: {err_list}')
                    forweb['Default gw good'] = f'{good_count} / {chk_count}'
                else:
                    forweb['Default gw good'] = f'0 / 0'

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
                                err_count = err_count + 30

                good_count = chk_count - err_count
                forweb['Forwarding_enable'] = f'{good_count} / {chk_count}'

                #### IP forwardin is disaabled on linux clients
                chk_count = 0
                err_count = 0
                tasks = []
                for name in list_of_vmnames:
                    if dict_of_name_and_ostype[name] == 'linux' and name not in list_of_routers:
                        for forwarding in dict_of_name_fullcmd[name]['FORWARDING']:
                            if 'net.ipv4.ip_forward' in forwarding and forwarding.split()[2] != '0':
                                err_count = err_count + 150
                                errors['errors_noty'].append(f'Форвардинг пакетов включен на каком-то из клиентов')
                                errors['Форвардинг пакетов включен на каком-то из клиентов'] = 'err'
                            else:
                                chk_count = chk_count + 1

                good_count = chk_count - err_count
                forweb['Forwarding_disable'] = f'{good_count} / {chk_count}'

                #### DNS servers
                print('start def DNS')
                chk_count = 1
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
                forweb['dnsclient_ip_addr'] = f'{good_count} / {chk_count}'

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
                            err_count = err_count + 10
                            errors['errors_noty'].append(f'Не настроен маскарад: {router}')
                        good_count = chk_count - err_count
                        forweb['snat_nftables'] = f'{good_count} / {chk_count}'
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
                    forweb['Win Domain'] = f'{good_count} / {chk_count}'
                    

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
                forweb['joined_to_domain'] = f'{good_count} / {chk_count}'
                answer['dict_of_vmnames_hostname'] = dict_of_vmnames_hostname
                
                ########## MULTI ROUTES
                
                if len(list_of_routers) > 1 and len(bridges['pnet0']) != 1:
                    chk_count = len(list_of_routers) - 1
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
                            err_count = err_count + chk_count + 10
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
                                    err_count = err_count + 10
                    good_count = chk_count - err_count
                    forweb['multiroutes'] = f'{good_count} / {chk_count}'
                else:
                    forweb['multiroutes'] = f'0 / 0'



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
                    forweb['special'] = f'{good_count} / {chk_count}'



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
        forwebresult.update(tmpdict)
        forwebresult.update(answer)
        forwebresult.update(errors)
        forwebresult.update(forweb)
        forFileResult.update(forwebresult)
        os.remove('/tmp/chk.lock')
        lab_done = {}
        lab_done['lab_done'] = 'no'
        score = 0
        maxscore = 0
        for dict_element in forwebresult.values():
            if ' / ' in dict_element:
                dict_element = dict_element.replace(' ', '')
                sample = dict_element.split('/')
                score = score + int(sample[0])
                maxscore = maxscore + int(sample[1])
                if score == maxscore and len(errors['errors_noty']) == 0:
                    lab_done['lab_done'] = 'yes'
        forwebresult.update(lab_done)


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
        with open("/data/result.json", "a") as file:
                #json.dump(forwebresult, file)
                file.write(json.dumps(forFileResult, ensure_ascii=False) + '\n')
        print('start def final return')
        
        selected_names = ["lab_path", "status", "username", "time", "errors_noty", "errorinfo"]
    
            
        # Подстрока для поиска в именах
        substring = " / "

        # Создаем новый словарь, включающий элементы, удовлетворяющие обоим условиям
        selected_students = {name: forFileResult[name] 
                            for name in forFileResult 
                            if name in selected_names}        
        # return forwebresult
        score = 0
        maxscore = 0
        for line in forFileResult.values():
            if ' / ' in line:
                line = line.replace(' ', '')
                sample = line.split('/')
                score = score + int(sample[0])
                maxscore = maxscore + int(sample[1])
        
        if maxscore != 0:
            percent = score / maxscore * 100
            ocenka = 2
            if percent >= 86:
                ocenka = 5
            elif percent >= 71:
                ocenka = 4
            elif percent >= 51:
                ocenka = 3
            elif percent >= 0:
                ocenka = 2
            selected_students['score'] = f"{score} / {maxscore}"
            selected_students['Оценка'] = ocenka
        if username != "i.kushch":
            return selected_students
        else:
            return selected_students, forwebresult


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

