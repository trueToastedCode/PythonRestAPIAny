import requests
import random
import string
import json
import crypto
import binascii
from tinyec import ec

PROTOCOL, HOST, PORT = 'http', '0.0.0.0', '8080'

CREATE_USERS = False
CREATE_CHAT = False
REQUEST_CHAT_USERS = True
CHAT_EXEC = True

# region Create users
users = []
if CREATE_USERS:
    # create new users
    create_user_count = 2
    for i in range(create_user_count):
        username = 'user-' + ''.join(random.choice(string.digits) for i in range(8))
        password = 'password' + ''.join(random.choice(string.digits) for i in range(8))
        r = requests.post(f'{PROTOCOL}://{HOST}:{PORT}/create-user', data={
            'username': username,
            'password': password
        })
        if r.status_code != 200:
            print(f'Failure creating user {i+1}/{create_user_count}')
            print(r.text)
            exit(1)
        users.append(json.loads(r.text))
        print(f'User ({username}, {password}) created: "{r.text}"')
    with open('users.json', 'w') as file:
        json.dump(users, file, indent=2)
        file.close()
# load stored users
if len(users) == 0:
    with open('users.json', 'r') as file:
        users = json.load(file)
        file.close()
    if len(users) == 0:
        print('Warning, no users loaded!')
    else:
        print(f'Loaded {len(users)} stored users!')
# endregion

# region Create chat
chat_id = '1'
if CREATE_CHAT:
    r = requests.post(f'{PROTOCOL}://{HOST}:{PORT}/create-chat', data={
        'user1Id': users[0]['id'],
        'user2Id': users[1]['id']
    })
    if r.status_code != 200:
        print(f'Failure creating chat!')
        print(r.text)
        exit(1)
    chat_id = r.text
    print(f'Chat with id {chat_id} created!')
# endregion

# region Request chat users
chat_users = []
if REQUEST_CHAT_USERS:
    r = requests.get(f'{PROTOCOL}://{HOST}:{PORT}/get-chat-users', data={'chatId': chat_id})
    if r.status_code != 200:
        print('Failure requesting chat users!')
        print(r.text)
        exit(1)
    chat_users = json.loads(r.text)
    for i in range(len(chat_users)):
        public_key = json.loads(chat_users[i]['publicKey'])
        chat_users[i]['publicKey'] = ec.Point(crypto.curve, int(public_key['x']), int(public_key['y']))
    print(f'Requested and loaded {len(chat_users)} chat users!')
# endregion

# region Chat execute
if CHAT_EXEC:
# region Select user
    while True:
        user_index = input(f'Select user {0}-{len(users)-1}: ')
        try:
            user_index = int(user_index)
        except ValueError:
            continue
        if not (-1 < user_index < len(users)):
            continue
        user = users[user_index]
        break
    user_pub_key = user['privateKey'] * crypto.curve.g
    # endregion
    while True:
        inp = input('Check messages (0), Send message (1): ')
        if inp == '0':
            r = requests.get(f'{PROTOCOL}://{HOST}:{PORT}/get-chat-update', params={
                'userId': user['id'],
                'chatId': chat_id
            })
            if r.status_code != 200:
                print('Failure requesting message update!')
                print(r.text)
                continue
            user_messages = json.loads(r.text)
            for user_message in user_messages:
                encrypted_message_data = json.loads(user_message['encryptedMessage'])
                encrypted_message_data['ciphertextPubKey'] = json.loads(encrypted_message_data['ciphertextPubKey'])
                encrypted_message_raw = (
                    binascii.unhexlify(encrypted_message_data['ciphertext'].encode()),
                    binascii.unhexlify(encrypted_message_data['nonce'].encode()),
                    binascii.unhexlify(encrypted_message_data['authTag'].encode()),
                    ec.Point(crypto.curve, encrypted_message_data['ciphertextPubKey']['x'], encrypted_message_data['ciphertextPubKey']['y'])
                )
                print(f'[{user_message["onServerDate"]}] '
                      f'{"me" if user_message["senderUserId"] == user["id"] else user_message["senderUserName"]} -> '
                      f'{crypto.decrypt_ecc(encrypted_message_raw, user["privateKey"]).decode()}')
        elif inp == '1':
            # region Request new message
            r = requests.post(f'{PROTOCOL}://{HOST}:{PORT}/create-message', data={
                'userId': user['id'],
                'chatId': chat_id
            })
            if r.status_code != 200:
                print('Failure requesting creation of message!')
                print(r.text)
                continue
            message_id = r.text
            # endregion
            # region Send encrypted messages
            message = input('')
            message = message.encode()
            send_counter = 0
            for receiver_user in chat_users:
                encrypted_msg = crypto.get_ecc_encrypted_message_dict(crypto.encrypt_ecc(message, receiver_user['publicKey']))
                encrypted_msg['ciphertext'] = str(encrypted_msg['ciphertext'])[2:-1]
                encrypted_msg['nonce'] = str(encrypted_msg['nonce'])[2:-1]
                encrypted_msg['authTag'] = str(encrypted_msg['authTag'])[2:-1]
                r = requests.post(f'{PROTOCOL}://{HOST}:{PORT}/create-user-message', data={
                    'messageId': message_id,
                    'encryptedMessage': json.dumps(encrypted_msg),
                    'receiverUserId': receiver_user['id']
                })
                if r.status_code != 200:
                    print(f'Failure sending encrypted message for user {receiver_user["id"]}')
                    print(r.text)
                else:
                    send_counter += 1
            print(f'{send_counter} encrypted messages have been send to chat')
            # endregion
# endregion
