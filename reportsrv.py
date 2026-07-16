#!/root/pyenv/bin/python3
"""Сервер сводных отчётов для преподавателя.

Читает результаты студентов из per-student SQLite БД (result.db), которые
пишет проверяющий сервис на стороне студента (myapi_with_reload.py). Точка
монтирования студента /data/ ведёт в /alldata/students/{student}/ на этом узле,
поэтому БД доступна по пути /alldata/students/{student}/result.db.

Вся арифметика оценки уже посчитана на стороне студента и лежит в БД
(score, max_score, percent, grade, lab_done) — здесь ничего не пересчитываем,
только собираем и сводим в таблицу.

Шаблоны (в репозитории report-srv/templates/, на appliance /cfs/report-srv/templates):
    summary.html — сводная таблица по группе с выбором лаб;
    report.html  — детальный отчёт по группе и одной лабе (история попыток);
    ping.html    — живой опрос машин студентов группы.
"""

import os
import re
import json
import shutil
import logging
import sqlite3
import asyncio
import tempfile
from typing import List, Optional

import httpx
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Общий справочник названий проверок (см. check_labels.py). Fallback — пустой
# словарь, если модуль не задеплоен рядом: тогда показываются сырые ключи.
try:
    from check_labels import CHECK_LABELS
except ImportError:
    CHECK_LABELS = {}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
app.mount("/static", StaticFiles(directory="/cfs/report-srv/static"), name="static")
templates = Jinja2Templates(directory="/cfs/report-srv/templates")

# ------------------------------------------------------------------ конфигурация
STUDENTS_ROOT = '/alldata/students'      # /alldata/students/{student}/result.db
GROUPS_ROOT = '/alldata/groups'          # /alldata/groups/{group}/<лабы>
NODES_CSV = '/cfs/nodes.csv'

ONLINE_SRV = 'https://10.0.103.2:8000'   # сервис онлайна/IP/студентов по группе
USERS_BY_GROUP_URL = f'{ONLINE_SRV}/usersByGroup'
INTERNAL_VERIFY = False                  # внутренние сервисы с самоподписанным TLS

MOODLE_URL = 'http://10.5.7.2/webservice/rest/server.php'
MOODLE_TOKEN = os.environ["API_TOKEN"]

HTTP_TIMEOUT = 60.0


# ================================================================== внешние сервисы
async def get_users_online(user: str) -> str:
    """Возвращает network студента из nodes.csv или '404', если не найден."""
    import csv
    try:
        with open(NODES_CSV, 'r', newline='') as csvfile:
            for row in csv.DictReader(csvfile):
                if row['user'] == user:
                    return row['network'] or '404'
    except FileNotFoundError:
        logger.warning("nodes.csv не найден: %s", NODES_CSV)
    return '404'


async def fetch_student_data(url: str):
    """Живой опрос машины студента: {url}/ping."""
    try:
        async with httpx.AsyncClient(verify=INTERNAL_VERIFY, timeout=HTTP_TIMEOUT) as client:
            response = await client.get(f"{url}/ping")
            return response.json() if response.status_code == 200 else None
    except httpx.HTTPError as e:
        logger.warning("Ошибка опроса %s: %s", url, e)
        return None


async def students_by_group(url: str, group: str):
    try:
        async with httpx.AsyncClient(verify=INTERNAL_VERIFY, timeout=HTTP_TIMEOUT) as client:
            response = await client.post(f'{url}?group={group}')
            return response.json() if response.status_code == 200 else None
    except httpx.HTTPError as e:
        logger.warning("Ошибка usersByGroup %s: %s", group, e)
        return None


async def openlab_by_student(url: str):
    try:
        async with httpx.AsyncClient(verify=INTERNAL_VERIFY, timeout=HTTP_TIMEOUT) as client:
            response = await client.get(f"{url}/openlab")
            return response.json() if response.status_code == 200 else None
    except httpx.HTTPError as e:
        logger.warning("Ошибка openlab %s: %s", url, e)
        return None


async def ip_by_student(student: str):
    try:
        async with httpx.AsyncClient(verify=INTERNAL_VERIFY, timeout=HTTP_TIMEOUT) as client:
            response = await client.post(f'{ONLINE_SRV}/getip?user={student}')
            return response.json() if response.status_code == 200 else None
    except httpx.HTTPError as e:
        logger.warning("Ошибка getip %s: %s", student, e)
        return None


async def get_students_by_group(url: str, group: str):
    results = await asyncio.gather(students_by_group(url, group))
    return [r for r in results if r is not None]


async def get_students_data(addresses: List[str]):
    results = await asyncio.gather(*[fetch_student_data(u) for u in addresses])
    return [r for r in results if r is not None]


async def group_students(group: str) -> List[str]:
    """Список логинов студентов группы через сервис онлайна. [] если пусто/ошибка."""
    students_res = await get_students_by_group(USERS_BY_GROUP_URL, group.lower())
    if students_res and students_res[0]:
        return students_res[0]
    logger.warning("Пустой список студентов для группы %s", group)
    return []


# ================================================================== файловая система
async def get_group_pnet(path: str) -> List[str]:
    """Список каталогов (групп) внутри указанного пути."""
    def scandir():
        try:
            return [e.name for e in os.scandir(path) if e.is_dir()]
        except FileNotFoundError:
            return []
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, scandir)


async def get_labs_pnet(path: str) -> List[str]:
    """Имена файлов-лаб в каталоге группы, включая подпапку REMOTE."""
    def scanfile():
        try:
            files = [e.name for e in os.scandir(path) if e.is_file()]
        except FileNotFoundError:
            return []
        remote_path = os.path.join(path, 'REMOTE')
        if os.path.isdir(remote_path):
            files += [e.name for e in os.scandir(remote_path) if e.is_file()]
        return files
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, scanfile)


def lab_key(path_or_name: str) -> str:
    """Короткое имя лабы: '//GROUPS/OA-2501/KS24.unl' -> 'KS24', 'KS24.unl' -> 'KS24'."""
    base = path_or_name.rsplit('/', 1)[-1]
    return base.rsplit('.', 1)[0] if '.' in base else base


def natural_key(s: str):
    """Ключ натуральной сортировки: KS4 раньше KS21."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r'(\d+)', s)]


async def group_lab_names(group: str) -> List[str]:
    """Отсортированный список коротких имён лаб группы (для колонок/чекбоксов)."""
    raw = await get_labs_pnet(os.path.join(GROUPS_ROOT, group))
    seen, keys = set(), []
    for name in raw:
        if name.startswith('.') or name.endswith('.swp'):
            continue
        k = lab_key(name)
        if k not in seen:
            seen.add(k)
            keys.append(k)
    keys.sort(key=natural_key)
    return keys


# ================================================================== чтение БД студента
def _fetch_runs(conn) -> list:
    """Читает прогоны с полной детализацией из открытого соединения.

    Каждый прогон дополняется разбивкой по проверкам (items), штрафами
    (penalties) и списком замечаний (errors) — то же, что показывает дашборд
    студента, чтобы любую попытку можно было раскрыть с этими подробностями.
    """
    conn.row_factory = sqlite3.Row
    runs = [dict(r) for r in conn.execute("SELECT * FROM runs ORDER BY lab_path, id")]

    items_by_run: dict = {}
    try:
        for it in conn.execute("SELECT run_id, name, score, max FROM check_items ORDER BY id"):
            items_by_run.setdefault(it['run_id'], []).append(
                {'name': it['name'], 'score': it['score'], 'max': it['max']})
    except sqlite3.DatabaseError:
        pass  # старые БД без check_items

    for r in runs:
        r['items'] = items_by_run.get(r['id'], [])
        try:
            r['errors'] = json.loads(r['errors_json']) if r.get('errors_json') else []
        except (ValueError, TypeError):
            r['errors'] = []
        try:
            r['penalties'] = json.loads(r['penalties_json']) if r.get('penalties_json') else {}
        except (ValueError, TypeError):
            r['penalties'] = {}
        try:
            r['collected'] = json.loads(r['debug_json']) if r.get('debug_json') else {}
        except (ValueError, TypeError):
            r['collected'] = {}
        if not isinstance(r['collected'], dict):
            r['collected'] = {}
    return runs


def _read_runs_inplace(db_path: str):
    """Пробует прочитать runs, открыв БД прямо на mount. None при неудаче.

    Дешёвый путь для случаев, когда mount позволяет открыть файл: сначала
    mode=ro, затем immutable=1 (только основной файл БД, без -wal/-shm и без
    блокировок). Если и это не срабатывает (root_squash, POSIX-локи по сети),
    вызывающий откатывается на чтение через локальную копию.
    """
    for uri in (f"file:{db_path}?mode=ro", f"file:{db_path}?immutable=1"):
        conn = None
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5)
            return _fetch_runs(conn)
        except sqlite3.DatabaseError:
            pass
        finally:
            if conn is not None:
                conn.close()
    return None


def _read_runs_via_copy(db_path: str):
    """Копирует БД (и -wal/-shm) в локальный tmp и читает оттуда.

    БД студента лежит на сетевом mount с root_squash: reportsrv не может ни
    писать в чужой каталог, ни ставить POSIX-блокировки, которых SQLite требует
    даже для чтения, — отсюда 'unable to open database file'. Но сам файл
    читается (cat работает), поэтому копируем байты в локальный писабельный tmp
    и открываем уже там — это обходит и права, и блокировки, и различия версий
    SQLite. -wal копируем тоже, чтобы видеть ещё не зачекпойченные прогоны.
    """
    tmpdir = tempfile.mkdtemp(prefix='rsdb_')
    local = os.path.join(tmpdir, 'result.db')
    conn = None
    try:
        shutil.copyfile(db_path, local)
        for suffix in ('-wal', '-shm'):
            if os.path.exists(db_path + suffix):
                try:
                    shutil.copyfile(db_path + suffix, local + suffix)
                except OSError:
                    pass
        conn = sqlite3.connect(local, timeout=5)
        return _fetch_runs(conn)
    except (OSError, sqlite3.DatabaseError) as e:
        logger.warning("Ошибка чтения (copy) %s: %s", db_path, e)
        return []
    finally:
        if conn is not None:
            conn.close()
        shutil.rmtree(tmpdir, ignore_errors=True)


def _load_student_labs(db_path: str) -> dict:
    """Читает result.db студента (только на чтение — БД живая).

    Возвращает {lab_key: {'best': run, 'attempts': [run, ...], 'count': n}},
    где best — прогон с максимальным score. Пусто, если БД нет/ошибка.
    Блокирующая — вызывать через run_in_executor.
    """
    if not os.path.exists(db_path):
        return {}
    # Сначала пробуем открыть на месте (дёшево); если mount не даёт — через копию.
    runs = _read_runs_inplace(db_path)
    if runs is None:
        runs = _read_runs_via_copy(db_path)

    labs: dict = {}
    for r in runs:
        labs.setdefault(lab_key(r['lab_path']), []).append(r)

    result = {}
    for key, attempts in labs.items():
        best = max(attempts, key=lambda r: ((r['score'] if r['score'] is not None else -1),
                                            (r['percent'] or 0), r['id']))
        attempts.sort(key=lambda r: r['id'], reverse=True)  # история: новые сверху
        result[key] = {'best': best, 'attempts': attempts, 'count': len(attempts)}
    return result


async def get_student_labs(student: str) -> dict:
    db_path = os.path.join(STUDENTS_ROOT, student, 'result.db')
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _load_student_labs, db_path)


def _attempt_view(a: dict, best_id) -> dict:
    """Плоское представление попытки для шаблонов (report и модалка summary)."""
    return {
        'ts': a['ts'], 'clientip': a.get('clientip'), 'score': a['score'],
        'maxscore': a['max_score'], 'percent': a['percent'], 'grade': a['grade'],
        'done': bool(a['lab_done']), 'items': a['items'],
        'penalties': a['penalties'], 'errors': a['errors'],
        'collected': a.get('collected', {}),
        'is_best': a['id'] == best_id,
    }


# ================================================================== Moodle (имена)
async def fetch_global_groups(url, token, groupname):
    params = {'wstoken': token, 'wsfunction': 'core_cohort_get_cohorts',
              'moodlewsrestformat': 'json'}
    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=params)
        if response.status_code == 200:
            for cohort in response.json():
                if cohort['idnumber'] == groupname:
                    return await fetch_cohort_members(url, token, cohort['id'])
        else:
            logger.warning("Moodle API ошибка (cohorts): %s", response.status_code)
    return None


async def fetch_cohort_members(url, token, cohort_id):
    params = {'wstoken': token, 'wsfunction': 'core_cohort_get_cohort_members',
              'moodlewsrestformat': 'json', 'cohortids[0]': cohort_id}
    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=params)
        if response.status_code == 200:
            members = response.json()
            if members and 'userids' in members[0]:
                return await fetch_users_info(url, token, members[0]['userids'])
            logger.info("В глобальной группе %s нет участников.", cohort_id)
        else:
            logger.warning("Moodle API ошибка (members): %s", response.status_code)
    return None


async def fetch_users_info(url, token, user_ids):
    async with httpx.AsyncClient() as client:
        responses = await asyncio.gather(*[
            client.post(url, data={
                'wstoken': token, 'wsfunction': 'core_user_get_users_by_field',
                'moodlewsrestformat': 'json', 'field': 'id', 'values[0]': user_id
            }) for user_id in user_ids
        ])
    resultdata = []
    for response in responses:
        if response.status_code == 200 and response.json():
            user = response.json()[0]
            resultdata.append(f"{user.get('username')},{user.get('fullname')},{user.get('email')}")
        else:
            logger.warning("Moodle API ошибка (user): %s", response.status_code)
    return resultdata


def moodle_name_map(moodle_res) -> dict:
    """Строит {username: fullname} из ответа Moodle. {} при ошибке/отсутствии."""
    m = {}
    if isinstance(moodle_res, list):
        for line in moodle_res:
            parts = line.split(',')
            if len(parts) >= 2:
                m[parts[0]] = parts[1]
    return m


async def group_name_map(group: str) -> dict:
    return moodle_name_map(await fetch_global_groups(MOODLE_URL, MOODLE_TOKEN, group.lower()))


# ================================================================== онлайн-статус
async def student_online_info(student: str) -> str:
    """Строка статуса подключения студента для отчётов/пинга."""
    address = await get_users_online(student)
    if address == '404':
        return 'Не подключен'
    address = address.replace('0/24', '1')
    openlab = await openlab_by_student(f'http://{address}:8000')
    lab_part = (openlab if openlab and openlab != 'o' else 'Нет открытой лабы')
    if isinstance(lab_part, str):
        lab_part = lab_part.replace('/GROUPS', '')
    student_ip = await ip_by_student(student)
    status = student_ip.get('status') if isinstance(student_ip, dict) else student_ip
    return f"{status}, {lab_part}"


# ================================================================== /summary
@app.get("/summary", response_class=HTMLResponse)
async def summaryinfo(request: Request,
                      group: Optional[str] = Query(None),
                      labs: Optional[List[str]] = Query(None)):
    groupdirs = sorted(await get_group_pnet(GROUPS_ROOT))
    ctx = {"request": request, "groupdirs": groupdirs, "selected_group": group,
           "all_labs": [], "selected_labs": [], "rows": [], "labels": CHECK_LABELS}

    if not group or group not in groupdirs:
        return templates.TemplateResponse(request, "summary.html", ctx)

    all_labs = await group_lab_names(group)
    # Выбранные лабы (колонки). Если ничего не отмечено — показываем все.
    selected = [l for l in (labs or []) if l in all_labs] or all_labs

    students = await group_students(group)
    name_map = await group_name_map(group)
    labs_data = await asyncio.gather(*[get_student_labs(s) for s in students])

    rows = []
    for student, data in zip(students, labs_data):
        cells, total = {}, 0
        for lab in selected:
            info = data.get(lab)
            if info:
                b = info['best']
                attempts = [_attempt_view(a, b['id']) for a in info['attempts']]
                cells[lab] = {
                    'grade': b['grade'], 'score': b['score'], 'max': b['max_score'],
                    'percent': b['percent'], 'count': info['count'],
                    'done': bool(b['lab_done']), 'ts': b['ts'],
                    'attempts': attempts, 'latest': attempts[0] if attempts else None,
                }
                total += b['score'] or 0
            else:
                cells[lab] = None
        rows.append({'username': student, 'name': name_map.get(student, student),
                     'cells': cells, 'total': total})

    rows.sort(key=lambda r: r['name'].lower())
    ctx.update({"all_labs": all_labs, "selected_labs": selected, "rows": rows})
    return templates.TemplateResponse(request, "summary.html", ctx)


# ================================================================== /report
@app.get("/report", response_class=HTMLResponse)
async def read_report(request: Request,
                      group: Optional[str] = Query(None),
                      lab: Optional[str] = Query(None)):
    groupdirs = sorted(await get_group_pnet(GROUPS_ROOT))
    dict_of_labs = dict(zip(groupdirs,
                            await asyncio.gather(*[group_lab_names(g) for g in groupdirs])))
    ctx = {"request": request, "groupdirs": groupdirs, "dict_of_labs": dict_of_labs,
           "selected_group": group, "selected_lab": lab, "students": [], "labels": CHECK_LABELS}

    if not group or group not in groupdirs or not lab:
        return templates.TemplateResponse(request, "report.html", ctx)

    key = lab_key(lab)
    students = await group_students(group)
    name_map = await group_name_map(group)
    labs_data = await asyncio.gather(*[get_student_labs(s) for s in students])
    online = await asyncio.gather(*[student_online_info(s) for s in students])

    rows = []
    for student, data, info_addr in zip(students, labs_data, online):
        name = name_map.get(student, student)
        labinfo = data.get(key)
        if not labinfo:
            rows.append({'username': name, 'info': info_addr, 'status': 'Не выполнялось',
                         'lab_path': f'/GROUPS/{group}/{lab}', 'history': [], 'trycount': 0})
            continue
        b = labinfo['best']
        attempts = [_attempt_view(a, b['id']) for a in labinfo['attempts']]
        rows.append({
            'username': name, 'info': info_addr, 'status': b['grade'],
            'lab_path': b['lab_path'], 'score': b['score'], 'maxscore': b['max_score'],
            'percent': b['percent'], 'grade': b['grade'], 'done': bool(b['lab_done']),
            'trycount': labinfo['count'], 'errors': b['errors'], 'attempts': attempts,
        })

    rows.sort(key=lambda r: r['username'].lower())
    ctx["students"] = rows
    return templates.TemplateResponse(request, "report.html", ctx)


# ================================================================== /ping, /info
async def build_ping_rows(group: str) -> List[dict]:
    """Живой опрос машин студентов группы: подключённые отдают ping-данные,
    остальные помечаются как не подключённые."""
    students_list = await group_students(group)
    addresses = []
    for student in students_list:
        address = await get_users_online(student)
        if address != '404':
            addresses.append(f"http://{address.replace('0/24', '1')}:8000")

    raw = await get_students_data(addresses)
    students, remaining = [], list(students_list)
    for data in raw:
        if data.get('username') in remaining:
            remaining.remove(data['username'])
        score = maxscore = 0
        for line in data.values():
            if isinstance(line, str) and ' / ' in line:
                sample = line.replace(' ', '').split('/')
                try:
                    score += int(sample[0])
                    maxscore += int(sample[1])
                except ValueError:
                    pass
        data['score'] = f'{score}/{maxscore}'
        students.append(data)

    for student in remaining:
        students.append({'username': student, 'status': 'Не подключен',
                         'errorinfo': 'Не подключен'})
    return students


async def render_ping(request: Request, group: Optional[str] = None):
    students = await build_ping_rows(group) if group else []
    return templates.TemplateResponse(request, "ping.html", {"students": students, "labels": CHECK_LABELS})


@app.get("/info", response_class=HTMLResponse)
async def infoindex(request: Request):
    return await render_ping(request)


@app.get("/info/{group}", response_class=HTMLResponse)
async def infogroup(request: Request, group: str):
    return await render_ping(request, group)


@app.get("/ping", response_class=HTMLResponse)
async def pingindex(request: Request):
    return await render_ping(request)


@app.get("/ping/{group}", response_class=HTMLResponse)
async def pinggroup(request: Request, group: str):
    return await render_ping(request, group)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="10.90.0.13", port=8008,
                ssl_keyfile="/root/webapp.key",
                ssl_certfile="/cfs/report-srv/webapp.crt",
                ssl_ca_certs="/cfs/report-srv/cacert.pem")
