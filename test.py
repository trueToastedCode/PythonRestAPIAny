import requests
import random
import string
import base64
import json
import os

URL = 'http://0.0.0.0:8080'

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
        r = requests.post(URL + '/api/users', json={'username': username, 'password': password, 'role': user_role})
        if r.status_code != 201:
            print(r.text)
            exit(1)
        users.append({'username': username, 'password': password, 'role': user_role})
        print(f'"{username}:{password}" as "{user_role}" created!')
    with open(TEST_USERS_FILE, 'w') as file:
        json.dump(users, file, indent=2)
        file.close()
# endregion

# region requests session and test roles
def get_auth_header(username: str, password: str) -> str:
    return 'Basic ' + base64.b64encode(f'{username}:{password}'.encode('utf-8')).decode('utf-8')

for user in users:
    print('####################')
    # create session
    session = requests.session()
    session.headers['Authorization'] = get_auth_header(user['username'], user['password'])
    r = session.get(URL + '/api/token')
    if r.status_code != 200:
        print(r.text)
        exit(1)
    token = r.json()['token']
    session.headers['Authorization'] = get_auth_header(token, None)
    print(f'Session for user "{user["username"]}" instantiated!')
    # request resources
    paths = ['/api/resource', '/api/resource-critical']
    for path in paths:
        print('----------')
        print(f'Testing "{path}" "{user["username"]}" with role "{user["role"]}"')
        print('->', session.get(URL + path).text.rstrip())
# endregion
