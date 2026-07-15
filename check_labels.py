"""Единый справочник человекочитаемых названий проверок.

Используется и автопроверкой (myapi_with_reload.py), и сервером отчётов
(reportsrv.py). Внутренние ключи проверок при этом не меняются — они нужны
для CHECK_WEIGHTS/PENALTIES и хранятся в check_items. Новые пункты проверок
добавляйте здесь, в одном месте.

При деплое этот файл должен лежать рядом с обоими скриптами, чтобы
`import check_labels` работал (директория скрипта попадает в sys.path).
"""

CHECK_LABELS = {
    'Hostnames': 'Имена узлов',
    'Ip Addresses': 'IP-адреса',
    'Networks': 'Сети в L2-доменах',
    'nodup_ipaddr': 'Уникальность IP-адресов',
    'IP is private': 'Приватные адреса',
    'Default gw present': 'Шлюз по умолчанию задан',
    'Default gw good': 'Шлюз по умолчанию корректен',
    'Forwarding_enable': 'Форвардинг на маршрутизаторах',
    'Forwarding_disable': 'Форвардинг на клиентах',
    'dnsclient_ip_addr': 'DNS-клиент',
    'snat_nftables': 'SNAT (nftables)',
    'Win Domain': 'Домен Windows',
    'joined_to_domain': 'Ввод узлов в домен',
    'multiroutes': 'Маршруты между сетями',
    'special': 'Спецпроверки лабы',
}


def label(name):
    """Человекочитаемое имя проверки; неизвестный ключ возвращается как есть."""
    return CHECK_LABELS.get(name, name)
