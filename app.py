from flask import Flask, request, Response
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import parse_qs
import crypto
import json

# region Config
HOST, PORT = '0.0.0.0', '8080'
DATA_BANK_FILE_NAME = 'database.db'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DATA_BANK_FILE_NAME
db = SQLAlchemy(app)
# endregion

def are_keys(p_dic: dict, p_keys: list):
    for key in p_keys:
        if key not in p_dic.keys() or p_dic[key] is None:
            return key
    return None

def dict_query_bytes(querystring: bytes) -> dict:
    params = parse_qs(querystring.decode())
    return {k: v[0] for k, v in params.items()}

@app.route('/create-user', methods=['POST'])
def create_user():
    cont = request.form.to_dict(flat=True)
    # check key existence
    first_missing_key = are_keys(cont, [User.KEY_USERNAME, User.KEY_PASSWORD])
    if first_missing_key:
        return Response(f'Key "{first_missing_key}" is missing!', status=500, mimetype='text/plain')
    # create user
    key_pair = crypto.generate_keys()
    user = User(
        username=cont[User.KEY_USERNAME],
        password_hash=crypto.get_hashed(cont[User.KEY_PASSWORD].encode('utf-8')).hexdigest(),
        private_key_encrypted=str(crypto.encrypt_fernet(data=cont[User.KEY_PASSWORD].encode('utf-8'), key=cont[User.KEY_PASSWORD]))[2:-1],
        public_key=json.dumps({'x': key_pair['publicKey'].x, 'y': key_pair['publicKey'].y}),
        last_chat_update_date=None
    )
    db.session.add(user)
    db.session.commit()
    # respond
    return Response(json.dumps({
        'id': str(user.id),
        User.KEY_PRIVATE_KEY: key_pair['privateKey'],
    }), status=200, mimetype='application/json')

@app.route('/create-chat', methods=['POST'])
def create_chat():
    cont = request.form.to_dict(flat=True)
    # check key existence
    first_missing_key = are_keys(cont, ['user1Id', 'user2Id'])
    if first_missing_key:
        return Response(f'Key "{first_missing_key}" is missing!', status=500, mimetype='text/plain')
    user1 = db.session.query(User).filter_by(id=cont['user1Id']).first()
    if not user1:
        return Response(f'User with id "{user1}" not found!', status=500, mimetype='text/plain')
    user2 = db.session.query(User).filter_by(id=cont['user2Id']).first()
    if not user2:
        return Response(f'User with id "{user2}" not found!', status=500, mimetype='text/plain')
    chat = Chat()
    db.session.add(chat)
    chat.users.append(user1)
    chat.users.append(user2)
    db.session.commit()
    return Response(str(chat.id), status=200, mimetype='text/plain')

@app.route('/get-chat-users', methods=['GET'])
def get_chat_users():
    cont = request.form.to_dict(flat=True)
    # check key existence
    first_missing_key = are_keys(cont, ['chatId'])
    if first_missing_key:
        return Response(f'Key "{first_missing_key}" is missing!', status=500, mimetype='text/plain')
    chat = db.session.query(Chat).filter_by(id=cont['chatId']).first()
    if not chat:
        return Response(f'User with id "{chat.id}" not found!', status=500, mimetype='text/plain')
    chat_users = list(map(lambda user: {
        'id': user.id,
        'username': user.username,
        'publicKey': user.public_key
    }, chat.users.all()))
    return Response(json.dumps(chat_users), status=200, mimetype='application/json')

@app.route('/get-chat-update', methods=['GET'])
def get_chat_update():
    cont = dict_query_bytes(request.query_string)
    # check key existence
    first_missing_key = are_keys(cont, ['chatId', 'userId'])
    if first_missing_key:
        return Response(f'Key "{first_missing_key}" is missing!', status=500, mimetype='text/plain')
    # check instances
    chat = db.session.query(Chat).filter_by(id=cont['chatId']).first()
    if not chat:
        return Response(f'Chat with id "{cont["chatId"]}" not found!', status=500, mimetype='text/plain')
    user = chat.users.filter_by(id=cont['userId']).first()
    if not user:
        return Response(f'User with id "{cont["userId"]}" is not in chat with id "{cont["chatId"]}"', status=500, mimetype='text/plain')
    # check messages
    # if user.last_chat_update_date is None:
    #     messages = chat.messages
    # else:
    #     messages = chat.messages.filter(Message.invoicedate >= user.last_chat_update_date)
    messages = chat.messages
    user.last_chat_update_date = datetime.datetime.utcnow()
    db.session.commit()
    data = []
    for message in messages:
        for user_message in message.user_messages:
            sender_user = chat.users.filter_by(id=message.sender_user_id).first()
            if user_message.receiver_user_id == int(cont['userId']):
                data.append({
                    'senderUserId': str(sender_user.id),
                    'senderUserName': sender_user.username,
                    'onServerDate': message.on_server_date.strftime('%Y-%m-%d %H:%M:%S'),
                    'encryptedMessage': user_message.encrypted_message
                })
    return Response(json.dumps(data), status=200, mimetype='application/json')

@app.route('/create-message', methods=['POST'])
def create_message():
    cont = request.form.to_dict(flat=True)
    # check key existence
    first_missing_key = are_keys(cont, ['chatId', 'userId'])
    if first_missing_key:
        return Response(f'Key "{first_missing_key}" is missing!', status=500, mimetype='text/plain')
    # check instances
    chat = db.session.query(Chat).filter_by(id=cont['chatId']).first()
    if not chat:
        return Response(f'Chat with id "{cont["chatId"]}" not found!', status=500, mimetype='text/plain')
    user = chat.users.filter_by(id=cont['userId']).first()
    if not user:
        return Response(f'User with id "{cont["userId"]}" is not in chat with id "{cont["chatId"]}"', status=500, mimetype='text/plain')
    # create message
    on_server_date = datetime.datetime.utcnow()
    message = Message(
        chat_id=chat.id,
        sender_user_id=user.id,
        on_server_date=on_server_date
    )
    db.session.add(message)
    db.session.commit()
    return Response(str(message.id), status=200, mimetype='text/plain')

@app.route('/create-user-message', methods=['POST'])
def create_user_message():
    cont = request.form.to_dict(flat=True)
    # check key existence
    first_missing_key = are_keys(cont, ['messageId', 'encryptedMessage', 'receiverUserId'])
    if first_missing_key:
        return Response(f'Key "{first_missing_key}" is missing!', status=500, mimetype='text/plain')
    # check instances
    message = db.session.query(Message).filter_by(id=cont['messageId']).first()
    if not message:
        return Response(f'Message with id "{cont["messageId"]}" was not found!', status=500, mimetype='text/plain')
    receiver_user = db.session.query(User).filter_by(id=cont['receiverUserId']).first()
    if not receiver_user:
        return Response(f'User with id "{cont["messageId"]}" was not found!', status=500, mimetype='text/plain')
    # TODO implement check if user is in chat which the message belongs to
    # create user message
    user_message = UserMessage(encrypted_message=cont['encryptedMessage'], receiver_user_id=receiver_user.id)
    message.user_messages.append(user_message)
    db.session.commit()
    return Response(status=200)

if __name__ == '__main__':
    from model import *

    # db.create_all()
    app.run(host=HOST, port=PORT)
