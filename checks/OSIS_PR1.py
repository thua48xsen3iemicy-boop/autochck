"""Доп. проверки лабы OSIS_PR1: разделы/fstab на FS, ключ и SSH на SSHDSRV.

Перенесено из блока `if 'OSIS_PR1.unl' in lab_path` в myapi_with_reload.py
без изменения логики и баллов. На сервере лежит в /pnet/checks/OSIS_PR1.py.
"""

KEYFORCHK = '3PkBGcuy1vP4Op1JRSqY2PN2CEetwFMGA6dgHdRbWs1quL/u6A9+blPxJ17xb3HCWPiUhAACAj2m48ptzJ3sdYhu81pcV6TUa65cOJtt3FYcWa+KXnWdbY2eS3UgIYFfvQmjK'


async def check(ctx):
    chk_count = 28
    err_count = 0

    name = 'FS'
    ctx.answer['df-h'] = []
    out = await ctx.run(name, "ls -l /mnt/ |grep data && ls -l /mnt/ |grep 5gb && ls -l /mnt/ |grep 9gb && echo OKMOUNTPOINT")
    if 'OKMOUNTPOINT' not in out:
        ctx.error(f'Похоже не созданны какие-то mountpoints или имеют имена не по заданию: {name}')
        err_count += 3

    out = await ctx.run(name, "df -hT |grep data && df -hT |grep 5gb && df -hT |grep 9gb && echo OKMOUNTED")
    if 'OKMOUNTED' not in out:
        ctx.error(f'Похоже какието разделы не смонтированны: {name}')
        err_count += 3
    for res in out.split('\n'):
        ctx.answer['df-h'].append(res)
    if ctx.answer['df-h'][0] == 'NONE':
        err_count += 9
    else:
        vdb1 = any('data' in res and 'ext3' in res for res in ctx.answer['df-h'])
        vdc1 = any('5gb' in res and 'ext4' in res for res in ctx.answer['df-h'])
        vdc2 = any('9gb' in res and 'ext3' in res for res in ctx.answer['df-h'])
        if not (vdb1 and vdc1 and vdc2):
            err_count += 3
            ctx.error(f'Похоже файловые системы не по заданию: {name}')
        # Проверка fstab: размонтировать, mount -a, разделы должны вернуться
        await ctx.run(name, "umount -f /mnt/data;umount -f /mnt/5gb;umount -f /mnt/9gb")
        await ctx.run(name, "mount -a")
        out = await ctx.run(name, "df -hT |grep data && df -hT |grep 5gb && df -hT |grep 9gb && echo OKMOUNTED")
        if 'OKMOUNTED' not in out:
            ctx.error(f'Похоже какието проблемы с конфигурацией fstab: {name}')
            err_count += 6

    name = 'SSHDSRV'
    out = await ctx.run(name, "ls / |grep -c keyfolder && echo FOLDEROK;ls /keyfolder/keyfile && echo FILEOK;cat /keyfolder/keyfile")
    if 'FOLDEROK' not in out:
        ctx.error(f'Каталог keyfolder не найден: {name}')
        err_count += 2
    if 'FILEOK' not in out:
        ctx.error(f'Файл keyfile не найден: {name}')
        err_count += 2
    if KEYFORCHK not in out:
        ctx.error(f'Содержимое файла keyfile не по заданию: {name}')
        err_count += 3

    out = await ctx.run(name, "ls /root/.ssh/authorized_keys && echo KEYSOK")
    if 'KEYSOK' not in out:
        ctx.error(f'Похоже аутентификация по ключам не настроенна: {name}')
        err_count += 3

    ctx.add_check('special', chk_count - err_count, chk_count)
