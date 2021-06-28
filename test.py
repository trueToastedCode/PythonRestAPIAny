import requests
import random
import string
import base64

URL = 'http://0.0.0.0:8080'

# create user
# username = 'user-' + ''.join(random.choice(string.digits) for i in range(8))
# password = 'password'
# print(requests.post(URL + '/api/users', json={'username': username, 'password': password}).text)

# request token
def get_auth_header(username: str, password: str, type: str = 'Basic') -> str:
    return type + ' ' + base64.b64encode(f'{username}:{password}'.encode()).decode()

session = requests.session()
session.headers['Authorization'] = get_auth_header('user-69302414', 'password')
token = session.get(URL + '/api/token').json()['token']

# use token to requests resource
session.headers['Authorization'] = get_auth_header(token, None)
print(session.get(URL + '/api/resource').text)
