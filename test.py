import requests
import random
import string
import json
import os

URL = 'http://192.168.0.32:8080'

# region load/create users
TEST_USERS_FILE = 'test_users.json'
user_roles = ['user', 'admin']
users = []
create_users = True
if os.path.exists(TEST_USERS_FILE):
    with open(TEST_USERS_FILE, 'r') as file:
        users = json.load(file)
        file.close()
    if len(users) != 0:
        create_users = False
        print(f'{len(users)} stored users loaded!')
if create_users:
    for user_role in user_roles:
        username = 'user-' + ''.join(random.choice(string.digits) for i in range(8))
        password = 'password'
        r = requests.post(URL + '/api/create-user', json={
            'username': username,
            'password': password,
            'role': user_role
        })
        if r.status_code != 201:
            print(r.text)
            exit(1)
        users.append({
            'username': username,
            'password': password,
            'role': user_role
        })
        print(f'"{username}:{password}" as "{user_role}" created!')
    with open(TEST_USERS_FILE, 'w') as file:
        json.dump(users, file, indent=2)
        file.close()
# endregion

for user in users:
    print('####################')
    # create session
    session = requests.session()
    r = session.post(URL + '/api/create-session', json={
        'username': user['username'],
        'password': user['password']
    })
    if r.status_code != 201:
        print(r.text)
        exit(1)
    session.headers['Authorization'] = r.json()['token']
    print(f'Session for user "{user["username"]}" instantiated!')
    # request resources
    paths = ['/api/resource', '/api/resource-critical', '/api/resource-critical']
    i, logout_at_count = 0, 2
    for path in paths:
        print('----------')
        print(f'Testing "{path}" with "{user["username"]}" with role "{user["role"]}"')
        print('->', session.get(URL + path).text.rstrip())
        i += 1
        if i == logout_at_count:
            r = session.post(URL + '/api/invalidate-session')
            if r.status_code != 200:
                print(r.text)
                exit(1)
            print('----------')
            print(f'Session for "{user["username"]}" invalidated!')
