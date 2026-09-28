"""Шаблон доп. проверок лабы.

Скопируйте в /pnet/checks/<имя лабы>.py — имя совпадает с файлом лабы без
расширения (KS24.unl -> KS24.py), для лабы с таким именем в любой группе.
Файл читается заново при каждой проверке: рестарт сервиса не нужен.
Лаба должна быть с маркером autocheck:on в description.

Доступно через ctx (см. LabCheckContext в myapi_with_reload.py):
    out = await ctx.run('NODE', 'команда')  # вывод; 'NONE', если узел не ответил
    ctx.error('текст')                     # ошибка в отчёт студенту
    ctx.add_check('Название', score, max)  # пункт оценки, score клампится в 0..max
    ctx.nodes, ctx.ostype                  # узлы лабы и их ОС ('linux', 'win', ...)
    ctx.lab_path, ctx.answer               # путь к .unl; словарь ответа (отладка)

Команды выполняются через qemu-guest-agent: только Linux (sh -c) и Windows
(cmd /c) узлы. Исключение в check() не ломает проверку лабы: студент увидит
«Ошибка в доп. проверке лабы», трейс — в логе сервиса.
Название пункта, которого нет в check_labels.py, показывается как есть.

Флаг ONLY_EXTRA = True: оценка лабы только по пунктам этого файла и
основным пунктам из KEEP (по умолчанию ['Hostnames']). Прочие основные
пункты, их штрафы и сообщения об ошибках исключаются из оценки и отчёта.
Без флага пункты файла просто добавляются к основным.
"""

# ONLY_EXTRA = True
# KEEP = ['Hostnames']


async def check(ctx):
    total, errs = 2, 0

    out = await ctx.run('SRV1', 'systemctl is-active nginx')
    if out.strip() != 'active':
        ctx.error('nginx не запущен: SRV1')
        errs += 1

    out = await ctx.run('SRV1', 'test -f /etc/nginx/sites-enabled/site && echo OK')
    if 'OK' not in out:
        ctx.error('Сайт не включён: SRV1')
        errs += 1

    ctx.add_check('Веб-сервер', total - errs, total)
