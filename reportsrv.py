#!/root/pyenv/bin/python3

from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import httpx
import ssl
import asyncio, os
import csv, json
from typing import List
import aiofiles
import json, re


app = FastAPI()

app.mount("/static", StaticFiles(directory="/cfs/report-srv/static"), name="static")
templates = Jinja2Templates(directory="/cfs/report-srv/templates")


async def get_users_online(user):
    #print('user', user)
    with open('/cfs/nodes.csv', 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        network = ""
        for row in reader:
            # print('rowuser', row['user'])
            if row['user'] == user:
                network = row['network']
        if network:
            return network
        else:
            # print(f'404 for user {user}')
            return "404"

async def fetch_student_data(url):
    try:
        #print('start for', url)

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(f"{url}/ping")
            return response.json() if response.status_code == 200 else None
    except httpx.TimeoutException:
        # Здесь можно добавить логику обработки таймаута
        print(f"Timeout occurred while fetching data from {url}")
        return None

async def students_by_group(url, group):
    
    try:
        #print('get students', url)
        
        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            response = await client.post(f'{url}?group={group}')
            return response.json() if response.status_code == 200 else None
    except httpx.TimeoutException:
        # Здесь можно добавить логику обработки таймаута
        print(f"Timeout occurred while fetching data from {url}")
        return None

async def openlab_by_student(url):
    try:
        #print('start for', url)

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(f"{url}/openlab")
            return response.json() if response.status_code == 200 else None
    except httpx.TimeoutException:
        # Здесь можно добавить логику обработки таймаута
        print(f"Timeout occurred while fetching data from {url}")
        return None

async def get_online():
    try:
        #print('start for', url)

        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            response = await client.get(f"https://10.0.103.2:8000/users")
            return response.json() if response.status_code == 200 else None
    except httpx.TimeoutException:
        # Здесь можно добавить логику обработки таймаута
        print(f"Timeout occurred while fetching online users")
        return None

async def ip_by_student(student):
    try:
        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            response = await client.post(f'https://10.0.103.2:8000/getip?user={student}')
            # print('ip resp', response.json())
            return response.json() if response.status_code == 200 else None
    except httpx.TimeoutException:
        # Здесь можно добавить логику обработки таймаута
        print(f"Timeout occurred while fetching data from getip")
        return None

async def get_students_by_group(url, group):
    tasks = [students_by_group(url, group)]
    results = await asyncio.gather(*tasks)
    # Убедитесь, что возвращаются только успешные результаты
    return [result for result in results if result is not None]
 
async def get_students_data(addresses):
    tasks = [fetch_student_data(url) for url in addresses]
    results = await asyncio.gather(*tasks)
    # Убедитесь, что возвращаются только успешные результаты
    return [result for result in results if result is not None]

async def get_group_pnet(path: str) -> List[str]:
    # Асинхронная функция, которая возвращает список каталогов внутри указанного пути
    def scandir():
        return [entry.name for entry in os.scandir(path) if entry.is_dir()]

    loop = asyncio.get_running_loop()
    dirs = await loop.run_in_executor(None, scandir)
    return dirs

# async def get_labs_pnet(path: str) -> List[str]:
#     # Асинхронная функция, которая возвращает список каталогов внутри указанного пути
#     def scanfile():
#         return [entry.name for entry in os.scandir(path) if entry.is_file()]

#     loop = asyncio.get_running_loop()
#     files = await loop.run_in_executor(None, scanfile)
#     return files

async def get_labs_pnet(path: str) -> List[str]:
    def scanfile():
        files = [entry.name for entry in os.scandir(path) if entry.is_file()]
        remote_path = os.path.join(path, 'REMOTE')
        if os.path.exists(remote_path) and os.path.isdir(remote_path):
            files += [entry.name for entry in os.scandir(remote_path) if entry.is_file()]
        return files

    loop = asyncio.get_running_loop()
    files = await loop.run_in_executor(None, scanfile)
    return files


async def read_json_file(file_path):
    if not os.path.exists(file_path):
        return None  # или возбудите исключение, если файл должен существовать
    data = []
    async with aiofiles.open(file_path, 'r') as file:
        async for line in file:
            try:
                json_object = json.loads(line.strip())
                data.append(json_object)
            except json.JSONDecodeError as e:
                print(f"Ошибка декодирования JSON {file_path}: {e}")
    return data

def parse_time(item):
    return datetime.datetime.strptime(item['time'], '%d.%m.%Y %H:%M')

path_to_labs = '/alldata/groups'
path_studata = '/alldata/students'
  

async def fetch_global_groups(url, token, groupname):
    function = 'core_cohort_get_cohorts'
    params = {
        'wstoken': token,
        'wsfunction': function,
        'moodlewsrestformat': 'json'
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=params)
        
        if response.status_code == 200:
            cohorts = response.json()
            for cohort in cohorts:
                if cohort['idnumber'] == groupname:
                    result = await fetch_cohort_members(url, token, cohort['id'])
                    return result
        else:
            return "Произошла ошибка при запросе к Moodle API:", response.status_code

async def fetch_cohort_members(url, token, cohort_id):
    function = 'core_cohort_get_cohort_members'
    params = {
        'wstoken': token,
        'wsfunction': function,
        'moodlewsrestformat': 'json',
        'cohortids[0]': cohort_id
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=params)
        
        if response.status_code == 200:
            members = response.json()
            # print(members)
            # Проверка наличия пользователей в первой глобальной группе
            if members and 'userids' in members[0]:
                # print(f"Участники глобальной группы с ID {cohort_id}:")
             
                result = await fetch_users_info(url, token, members[0]['userids'])
                return result
            else:
                print(f"В глобальной группе с ID {cohort_id} нет участников.")
        else:
            print("Произошла ошибка при запросе к Moodle API:", response.status_code)

async def fetch_users_info(url, token, user_ids):
    function = 'core_user_get_users_by_field'
    field = 'id'
    
    async with httpx.AsyncClient() as client:
        responses = await asyncio.gather(*[
            client.post(url, data={
                'wstoken': token,
                'wsfunction': function,
                'moodlewsrestformat': 'json',
                'field': field,
                f'values[0]': user_id
            }) for user_id in user_ids
        ])
        resultdata = []
        for response in responses:
            if response.status_code == 200:
                user_info = response.json()
                #print('USERINFO', user_info)
                if user_info:
                    # Предполагается, что ответ содержит информацию о одном пользователе, поэтому берем первый элемент
                    # print(user_info)
                    user = user_info[0]
                    # username_tmp = user.get('username').split('_')[0]
                    # username_tmp2 = user.get('username').split('_')[1]
                    # print(f"MOODLE {username_tmp}")
                    # resultdata.append(f"{username_tmp + '_' + username_tmp2},{user.get('fullname')},{user.get('email')}")

                    resultdata.append(f"{user.get('username')},{user.get('fullname')},{user.get('email')}")
                else:
                    print("Пользователь не найден.")
            else:
                print("Произошла ошибка при запросе к Moodle API:", response.status_code)
        #print('return names', resultdata) 
        return resultdata

url = 'http://10.5.7.2/webservice/rest/server.php'
token = os.environ["API_TOKEN"]


@app.get("/summary", response_class=HTMLResponse)
async def summaryinfo(request: Request, group: str = Query(None)):
    dirs = await get_group_pnet(path_to_labs)
    students_results = {}
    students_rating = {}
    students_count = {}
    list_of_labs = []
    if group:
        students_res = await get_students_by_group('https://10.0.103.2:8000/usersByGroup', group.lower())
        moodle_res = await fetch_global_groups(url, token, group.lower())
        students_list = students_res[0]
        list_of_labs_tmp = await get_labs_pnet(f'/alldata/groups/{group}')
        for lab in list_of_labs_tmp:
            if 'KS' in lab:
                list_of_labs.append(lab)
        # list_of_labs.sort()
        list_of_labs.sort(key=lambda s: [int(text) if text.isdigit() else text.lower() for text in re.split('(\d+)', s)])
        for student in students_list:
            
            students_results[student] = {}
            students_rating[student] = 0
            students_count[student] = 0 
            summscore = 0
            summcount = 0
            list_of_results_tmp = await read_json_file(f'{path_studata}/{student}/result.json')
            if list_of_results_tmp is None:
                list_of_results_tmp = []
            for lab in list_of_labs:
                count = 0
                summscore_tmp = 0
                
                students_results[student][lab] = {}
                students_results[student][lab]['best'] = 0
                students_results[student][lab]['maxscore'] = 0
                students_results[student][lab]['ocenka'] = 2
                for lab_result in list_of_results_tmp:
                    if lab in lab_result['lab_path']:
                        count = count + 1
                        score = 0
                        
                        maxscore = 0
                        for line in lab_result.values():
                            if ' / ' in line:
                                line = line.replace(' ', '')
                                sample = line.split('/')
                                score = score + int(sample[0])
                                maxscore = maxscore + int(sample[1])
                        if maxscore != 0:
                            percent = score / maxscore * 100
                        else:
                            percent = 0
                        ocenka = 2
                        if percent >= 86:
                            ocenka = 5
                        elif percent >= 71:
                            ocenka = 4
                        elif percent >= 51:
                            ocenka = 3
                        elif percent >= 0:
                            ocenka = 2
                        if score > students_results[student][lab]['best']:
                            students_results[student][lab]['best'] = score
                            students_results[student][lab]['maxscore'] = maxscore
                            students_results[student][lab]['ocenka'] = ocenka
                            summscore_tmp = score
                summscore = summscore + summscore_tmp
                summcount = summcount + count
                students_results[student][lab]['count'] = count
            students_rating[student] = summscore
            students_count[student] = summcount
            for moodle in moodle_res:
                # student0 = student.replace('zh', 'j').replace('cz', 'ch').replace('ja', 'ya')
                student0 = student
                if student0 in moodle:
                    student_tmp = moodle.split(',')[1]
                    students_results[student_tmp] = students_results.pop(student)
                    students_rating[student_tmp] = students_rating.pop(student)
                    students_count[student_tmp] = students_count.pop(student)
    

        return templates.TemplateResponse("summary.html", {"request": request, "students": students_results, "selected_group": group, "labs": list_of_labs, "rating": students_rating, "groupdirs": dirs, "trycount": students_count})
    else:
        return templates.TemplateResponse("summary.html", {"request": request, "students": students_results, "selected_group": group, "labs": list_of_labs, "rating": students_rating, "groupdirs": dirs, "trycount": students_count})






@app.get("/report", response_class=HTMLResponse)
async def read_report(request: Request, group: str = Query(None), lab: str = Query(None)):
    print('ip client', request.client.host)
    tmp_chk = request.query_params.get('group')
    if tmp_chk is not None:
        group_req = request.query_params['group']
    else:
        group_req = None
    tmp_chk = request.query_params.get('lab')
    if tmp_chk is not None:
        lab_req = request.query_params['lab']
    else:
        lab_req = None
    print('headers', group_req, lab_req)

    if group_req == None and lab_req == None:
        online_users = await get_online()
        for online_user in online_users:
            print(online_user)
        
    dict_of_labs = {}
    dirs = await get_group_pnet(path_to_labs)
    #print(dirs)
    for group_dir in dirs:
        list_of_labs = await get_labs_pnet(f'/alldata/groups/{group_dir}')
        list_of_labs_filtered = []
        for labs in list_of_labs:
            if '.swp' not in labs:
                #print('labs ______ ', labs)
                list_of_labs_filtered.append(labs)
        dict_of_labs[group_dir] = list_of_labs_filtered
    labexist = 0
    for tmplabs in dict_of_labs.values():
        if lab in tmplabs:
            labexist = 1
            break


    students = []
    scoresumm = {}
    trysumm = {}
    selected_group = request.query_params.get('group', default=None)
    selected_lab = request.query_params.get('lab', default=None)
    if group in dirs and labexist == 1:
        print(f'_______________________{group} _____________{lab}')
        students_res = await get_students_by_group('https://10.0.103.2:8000/usersByGroup', group.lower())
        moodle_res = await fetch_global_groups(url, token, group.lower())
        # print('moodle', moodle_res)
        # print('from api', students_res)
        students_list = students_res[0]
        #print('students_res', students_res)
        users_try_history = {}
        for student in students_list:
            try_history = []
            tmpbest = '0'
            list_of_results_tmp = await read_json_file(f'{path_studata}/{student}/result.json')
            list_of_results = []
            addresses = []
            address = await get_users_online(student)
            # print('address', address, 'for', student)
            if address != '404':
                address = address.replace('0/24', '1')
                openlab = await openlab_by_student(f'http://{address}:8000')
                if openlab == 'o':
                    openlab = 'Нет открытой лабы'
                student_ip = await ip_by_student(student)
                lab_part = (openlab or 'Нет открытой лабы').replace('/GROUPS', '')
                address = f"{student_ip['status']}, {lab_part}"
                # address = f"{student_ip['status']}, {openlab.replace('/GROUPS', '')}"
                print('openlab', openlab)
                # address = str(student_ip)

            else:
                address = "Не подключен"


            if list_of_results_tmp is not None:
                for element in list_of_results_tmp:
                    element.pop('dict_of_name_fullcmd', None)
                    element.pop('dbg', None)
                    element.pop('specout', None)
                    element.pop('dict_of_vmname_and_uid', None)
                    element.pop('dict_of_name_and_intname', None)
                    element.pop('dict_of_name_and_path', None)
                    element.pop('name_ostype', None)
                    element.pop('dict_of_intnames_ipaddr', None)
                    element.pop('dict_of_bridges_vmnames', None)
                    element.pop('dict_of_name_cisco_script', None)
                    element.pop('list_of_vmnames', None)
                    element.pop('list_of_intname', None)
                    element.pop('dict_of_name_routeros_script', None)
                    element.pop('dict_of_name_winservers_script', None)
                    element.pop('dict_of_intnames_network', None)
                    element.pop('bridges', None)
                    element.pop('mikrotik_raw_output', None)
                    element['info'] = address
                    for moodle in moodle_res:
                        if element['username'] in moodle:
                            element['username'] = moodle.split(',')[1]
                    list_of_results.append(element)
            



            if list_of_results is not None:
           
                list_of_results_by_lab = []
                list_for_answer = []
                list_try_history = []
                tmpdict = {}
                format_errnoty = ""

                for try_result in list_of_results:
                    if lab in try_result['lab_path'] and try_result['status'] == '200':
                        list_of_results_by_lab.append(try_result)

                oneuser_try_history = []
                for element in list_of_results_by_lab:
                    score = 0
                    maxscore = 0
                    if 'clientip' not in element.keys():
                        element['clientip'] = 'NONE'
                    else:
                        tmpip = element['clientip']
                        if '10.0.145.' in tmpip:
                            element['clientip'] = 'K45' + '-' + tmpip.replace('10.0.145.','')
                    for line in element.values():
                        if ' / ' in line:
                            line = line.replace(' ', '')
                            sample = line.split('/')
                            score = score + int(sample[0])
                            maxscore = maxscore + int(sample[1])
                  
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

                    oneuser_try_history.append(element['time'] + ' ' + str(score) + '/' + str(maxscore) + ' ' + str(ocenka) + ' ' + element['clientip'])
                users_try_history[student] = oneuser_try_history
                history_forreport = ""
                trycount = 0
                for element in oneuser_try_history:
                    history_forreport = history_forreport + '<br>' + element
                    trycount = trycount + 1
                maxscore = 0
                if list_of_results_by_lab:
                    try_result = list_of_results_by_lab[-1]
                    score = 0
                    maxscore = 0
                    for line in try_result.values():
                        if ' / ' in line:
                            line = line.replace(' ', '')
                            sample = line.split('/')
                            score = score + int(sample[0])
                            maxscore = maxscore + int(sample[1])
                    scoresumm['score'] = score
                    scoresumm['maxscore'] = maxscore
                    tmpdict['try_history'] = history_forreport
                    tmpdict['trycount'] = trycount
                    
                    percent = score / maxscore * 100
                    ocenka = 2
                    tmpdict['ocenka'] = 2
                    if percent >= 86:
                        tmpdict['ocenka'] = 5
                    elif percent >= 71:
                        tmpdict['ocenka'] = 4
                    elif percent >= 51:
                        tmpdict['ocenka'] = 3
                    elif percent >= 0:
                        tmpdict['ocenka'] = 2
                    try_result['status'] = tmpdict['ocenka']    
                    try_result.update(scoresumm)
                    try_result.update(tmpdict)

                    for element in try_result['errors_noty']:
                        format_errnoty = format_errnoty + element + '<br>'
                    try_result['errors_noty'] = format_errnoty

                else:
                    try_result = {}
                    # if str(maxscore) == '':  
                    #     maxscore = 0
                    try_result['maxscore'] = maxscore
                    tmpstudent = ''
                    for moodle in moodle_res:
                        student0 = student.replace('zh', 'j').replace('cz', 'ch').replace('ja', 'ya')
                        if student0 in moodle:
                            tmpstudent = moodle.split(',')[1]
                    if tmpstudent != '':
                        try_result['username'] = tmpstudent
                    else:
                        try_result['username'] = student
                    try_result['status'] = '2'
                    try_result['lab_path'] = '/GROUPS/' + group + '/' + lab
                    try_result['info'] = address
                students.append(try_result)
                             
            else:
                print('No results')
                try_result = {}
                try_result['username'] = student
                try_result['info'] = address
                try_result['status'] = 'Не выполнялось'
                try_result['lab_path'] = '/GROUPS/' + group + '/' + lab
                students.append(try_result)


    
    print('dict labs', dict_of_labs)
    print('users history', students)
    return templates.TemplateResponse("report.html", {"request": request, "students": students, "groupdirs": dirs, "dict_of_labs": dict_of_labs, "selected_group": selected_group, "selected_lab": selected_lab})


@app.get("/info", response_class=HTMLResponse)
async def infoindex(request: Request):
    students = [] 
    return templates.TemplateResponse("ping.html", {"request": request, "students": students})

@app.get("/info/{group}", response_class=HTMLResponse)
async def infogroup(request: Request, group: str):
    addresses = []

    students_res = await get_students_by_group('https://10.0.103.2:8000/usersByGroup', group)
    students_list = students_res[0]
    #students_list.append('student')
    print('students_list_________________________', students_list)

    for student in students_list:
        
        address = await get_users_online(student)
        print('address', address, 'for', student)
        if address != '404':
            address = address.replace('0/24', '1')
            addresses.append(f'http://{address}:8000')
    
    print('addressess', addresses)

    raw_students_data = await get_students_data(addresses)
    students = []
    processed_data = {}
    scoresumm = {}

    for data in raw_students_data:
        print('__________________________________', data)
        score = 0
        maxscore = 0
        students_list.remove(data['username'])
        #print('students_list', students_list)
        for line in data.values():
            if ' / ' in line:
                line = line.replace(' ', '')
                sample = line.split('/')
                score = score + int(sample[0])
                maxscore = maxscore + int(sample[1])
        
        scoresumm['score'] = f'{score}/{maxscore}'
        data.update(scoresumm)
        students.append(data)        

    for student in students_list:
        tmpdict = {}
        tmpdict['username'] = student
        tmpdict['status'] = 'Не подключен'
        tmpdict['errorinfo'] = 'Не подключен'
        #print('tmpdict', tmpdict)
        students.append(tmpdict)
    # Передать обработанные данные в шаблон
    #print('out data', students)
    return templates.TemplateResponse("ping.html", {"request": request, "students": students})

@app.get("/ping", response_class=HTMLResponse)
async def pingindex(request: Request):
    students = [] 
    return templates.TemplateResponse("ping.html", {"request": request, "students": students})

@app.get("/ping/{group}", response_class=HTMLResponse)
async def pinggroup(request: Request, group: str):
    addresses = []

    students_res = await get_students_by_group('https://10.0.103.2:8000/usersByGroup', group)
    students_list = students_res[0]
    #students_list.append('student')
    print('students_list_________________________', students_list)

    for student in students_list:
        
        address = await get_users_online(student)
        print('address', address, 'for', student)
        if address != '404':
            address = address.replace('0/24', '1')
            addresses.append(f'http://{address}:8000')
    
    print('addressess', addresses)

    raw_students_data = await get_students_data(addresses)
    students = []
    processed_data = {}
    scoresumm = {}

    for data in raw_students_data:
        print('__________________________________', data)
        score = 0
        maxscore = 0
        students_list.remove(data['username'])
        #print('students_list', students_list)
        for line in data.values():
            if ' / ' in line:
                line = line.replace(' ', '')
                sample = line.split('/')
                score = score + int(sample[0])
                maxscore = maxscore + int(sample[1])
        
        scoresumm['score'] = f'{score}/{maxscore}'
        data.update(scoresumm)
        students.append(data)        

    for student in students_list:
        tmpdict = {}
        tmpdict['username'] = student
        tmpdict['status'] = 'Не подключен'
        tmpdict['errorinfo'] = 'Не подключен'
        #print('tmpdict', tmpdict)
        students.append(tmpdict)
    # Передать обработанные данные в шаблон
    #print('out data', students)
    return templates.TemplateResponse("ping.html", {"request": request, "students": students})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="10.90.0.13", port=8008, ssl_keyfile="/root/webapp.key", ssl_certfile="/cfs/report-srv/webapp.crt", ssl_ca_certs="/cfs/report-srv/cacert.pem")
