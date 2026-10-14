"""Шаблон лабы с подготовкой (преднастроем) и индивидуальным вариантом.

Скопируйте в /pnet/checks/<имя лабы>.py (KS24.unl -> KS24.py) и поставьте в
description лабы маркеры autocheck:on и prepare:on. Тогда у студента, пока
эта лаба открыта, рядом с «Проверить» появится кнопка «Подготовить лабу»:
она выполняет prepare(ctx) на запущенных узлах. Проверка такой лабы не
запускается, пока лаба не подготовлена, и останавливается, если какой-то
подготовленный узел потом вайпнули (пропала метка подготовки) — студенту
предлагается подготовить лабу заново. Попытка try:N при этом не тратится.

Подготавливать пока можно только Linux-узлы.

Вариант студента (VARIANT, variant(v)) один и тот же при каждой подготовке
и проверке, у разных студентов — разный. Студент видит его на своей
странице в блоке «Ваш вариант» вместе с текстом TASK. Посмотреть варианты
заранее: python3 labprep.py /pnet/checks/<лаба>.py логин1 логин2 ...

Что есть для VARIANT (подробнее — в labprep.py):
    net(пул, префикс)          случайная сеть, не пересекается с другими
    nets(N, пул, префикс)      N таких сетей списком
    subnets('имя', префикс)    подсети уже выбранной сети (все или count=N)
    host_in('имя')             случайный адрес в сети (кроме первых 10)
    choice(a, b, c)            одно из значений
    number(от, до)             число
    text('user###')            строка: # — цифра, ? — буква
У сети: .host(1) (первый адрес, шлюз), .host(-1), .gw, .mask, .prefix,
.split(26). У адреса: str() — '10.1.2.10', .cidr — '10.1.2.10/24', .mask.

В prepare(ctx) (см. PrepareContext в labprep.py):
    await ctx.set_ip('узел', 'интерфейс', адрес, gw=..., dns=...)
    await ctx.set_hostname('узел', 'имя')
    await ctx.mkdir('узел', '/путь')
    await ctx.write_file('узел', '/путь', 'текст', mode=0o644)
    await ctx.shell('узел', 'любая команда sh')
Шаг, вернувший не 0, останавливает подготовку и показывается студенту.

В check(ctx) вариант доступен как ctx.v — так проверка знает, какие адреса
должны быть у этого студента.
"""

# SALT = '2026-осень'   # смена соли перемешивает варианты (лабу нужно подготовить заново)

VARIANT = {
    'lan': net('10.0.0.0/8', 24),
    'dmz': net('172.16.0.0/12', 28),
    'srv': host_in('lan'),
    'vlan': choice(10, 20, 30, 40),
    'site_user': text('user###'),
}


def variant(v):
    # Производные значения: шлюз — первый адрес сети
    v['gw'] = v['lan'].gw


TASK = ('Сеть LAN: {lan}, шлюз {gw}. Сервер SRV1 уже получил адрес {srv}. '
        'Настройте маршрутизатор R1 и выведите сайт пользователя {site_user} '
        'в сеть DMZ {dmz}.')


async def prepare(ctx):
    v = ctx.v
    await ctx.set_hostname('SRV1', 'srv1')
    await ctx.set_ip('SRV1', 'ens3', v['srv'], gw=v['gw'], dns='8.8.8.8')
    await ctx.mkdir('SRV1', f'/home/{v["site_user"]}/site')
    await ctx.write_file('SRV1', f'/home/{v["site_user"]}/site/index.html',
                         f'<h1>{v["site_user"]}</h1>\n')
    await ctx.shell('SRV1', f'id {v["site_user"]} >/dev/null 2>&1 || useradd -m {v["site_user"]}')


async def check(ctx):
    out = await ctx.run('SRV1', 'ip -4 -o addr show dev ens3')
    ok = ctx.v['srv'].cidr in out
    if not ok:
        ctx.error(f'На SRV1 нет адреса {ctx.v["srv"].cidr}')
    ctx.add_check('Адрес SRV1 из варианта', 1 if ok else 0, 1)
