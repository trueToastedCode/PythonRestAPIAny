from flask import Flask, jsonify, g, request, abort, Response
from flask_sqlalchemy import SQLAlchemy
import binascii
import hashlib
import os
import time
import threading
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired

DATABASE_FILE_NAME = 'db.sqlite3'
SESSIONS_CLEAN_CYCLE = 28800  # [seconds] 3 times every day
SESSION_EXPIRE_IN = 31536000  # [seconds] 1 year

app = Flask(__name__)
app.config['SECRET_KEY'] = '0190736d4746be24da347263cc057503'
app.config['SECURITY_PASSWORD_SALT'] = 'fa0de3aa1e2a8f67a7dcd1f93e2ac0ca'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DATABASE_FILE_NAME

db = SQLAlchemy(app)

class Roles:
    ADMIN = 'admin'
    SUPPORTER = 'supporter'
    USER = 'user'

def hash_password(password: str) -> str:
    return binascii.hexlify(hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                            app.config['SECURITY_PASSWORD_SALT'].encode('utf-8'), 1024)).decode('utf-8')

def session_required(roles=None):
    def decorator(function):
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                abort(401)  # token is missing
            session = Session.verify_auth_token(token)
            if not session:
                abort(401)  # invalid session
            user = User.query.get(session.user_id)
            if roles:
                user_roles = list(map(lambda user_role: user_role.name, user.roles))
                role_existent = False
                for role in roles:
                    if role in user_roles:
                        role_existent = True
                        break
                if not role_existent:
                    abort(401)  # missing role
            g.session = session
            g.user = user
            return function(*args, **kwargs)
        wrapper.__name__ = function.__name__
        return wrapper
    return decorator

def clean_sessions_cycle():
    def clean_sessions():
        now = int(time.time())
        sessions = Session.query.filter(Session.expire_timestamp < now).all()
        if sessions:
            for session in sessions:
                db.session.delete(session)
            db.session.commit()
        return len(sessions)
    while True:
        i = clean_sessions()
        print(f'Cleaned {i} outdated sessions!')
        time.sleep(SESSIONS_CLEAN_CYCLE)

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id')))

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expire_timestamp = db.Column(db.Integer, nullable=False)
    is_invalidated = db.Column(db.Boolean, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def generate_auth_token(self):
        s = Serializer(app.config['SECRET_KEY'], expires_in=self.expire_timestamp-int(time.time()))
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token: str):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        session = Session.query.get(data['id'])
        if session.is_invalidated:
            return None  # session has been invalidated
        return session

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    sessions = db.relationship('Session', backref='owner')
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    def verify_password(self, password: str) -> bool:
        return self.password_hash == hash_password(password)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), nullable=False)
    description = db.Column(db.String(255))

@app.route('/api/create-user', methods=['POST'])
def create_user():
    username, password, role = request.json.get('username'), request.json.get('password'), request.json.get('role')
    if username is None or password is None or role is None:
        abort(400)  # missing arguments
    if User.query.filter_by(username=username).first():
        abort(400)  # existing user
    role = Role.query.filter_by(name=role).first()
    if not role:
        abort(400)  # role not found
    user = User(username=username, password_hash=hash_password(password), roles=[role])
    db.session.add(user)
    db.session.commit()
    return Response(status=201)

@app.route('/api/create-session', methods=['POST'])
def create_session():
    username, password = request.json.get('username'), request.json.get('password')
    if username is None or password is None:
        abort(400)  # missing arguments
    user = User.query.filter_by(username=username).first()
    if not user:
        abort(400)  # user does not exist
    if not user.verify_password(password):
        abort(401)  # invalid password
    session = Session(expire_timestamp=int(time.time())+600, is_invalidated=False, user_id=user.id)
    db.session.add(session)
    db.session.commit()
    token = session.generate_auth_token()
    return jsonify({'token': token.decode('ascii'), 'duration': 600}), 201

@app.route('/api/invalidate-session', methods=['POST'])
@session_required()
def invalidate_session():
    g.session.is_invalidated = True
    db.session.commit()
    return Response(status=200)

@app.route('/api/resource')
@session_required()
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

@app.route('/api/resource-critical')
@session_required(roles=[Roles.ADMIN, Roles.SUPPORTER])
def get_resource_critical():
    return jsonify({'data': '(Critical) Hello, %s!' % g.user.username})

if __name__ == '__main__':
    if not os.path.exists(DATABASE_FILE_NAME):
        db.create_all()
        db.session.add(Role(name=Roles.ADMIN))
        db.session.add(Role(name=Roles.SUPPORTER))
        db.session.add(Role(name=Roles.USER))
        db.session.commit()
    threading.Thread(target=clean_sessions_cycle, args=(), kwargs={}).start()
    app.run(host='0.0.0.0', port='8080')
