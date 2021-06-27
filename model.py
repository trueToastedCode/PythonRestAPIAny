from app import db
import datetime

user_chat_lookup = db.Table('user_chat_lookup',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('chat_id', db.Integer, db.ForeignKey('chat.id'))
)

class User(db.Model):
    KEY_USERNAME = 'username'
    KEY_PASSWORD = 'password'
    KEY_PASSWORD_HASH = 'passwordHash'
    KEY_PUBLIC_KEY = 'publicKey'
    KEY_PRIVATE_KEY = 'privateKey'
    KEY_PRIVATE_KEY_ENCRYPTED = 'privateKeyEncrypted'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    public_key = db.Column(db.String, nullable=False)
    private_key_encrypted = db.Column(db.String, nullable=False)
    chats = db.relationship('Chat', secondary=user_chat_lookup, backref=db.backref('users', lazy='dynamic'))
    # user_messages = db.relationship('UserMessage', backref='owner')  # results in error
    last_chat_update_date = db.Column(db.DateTime, nullable=True, default=datetime.datetime.utcnow())

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    messages = db.relationship('Message', backref='owner')
    # backref users

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'))
    sender_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    on_server_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())
    user_messages = db.relationship('UserMessage', backref='owner')

class UserMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'))
    receiver_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    encrypted_message = db.Column(db.String, nullable=False)
