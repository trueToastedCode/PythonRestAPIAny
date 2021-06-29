from flask import Flask, jsonify, g, request, abort, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from flask_security import Security, SQLAlchemyUserDatastore
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
import os
import hashlib
import binascii

# https://blog.miguelgrinberg.com/post/restful-authentication-with-flask
# https://github.com/miguelgrinberg/REST-auth/blob/master/api.py
# https://flask-httpauth.readthedocs.io/en/latest/

DATABASE_FILE_NAME = 'db.sqlite3'
app = Flask(__name__)
app.config['SECRET_KEY'] = '0190736d4746be24da347263cc057503'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DATABASE_FILE_NAME
app.config['SECURITY_PASSWORD_SALT'] = 'fa0de3aa1e2a8f67a7dcd1f93e2ac0ca'
auth = HTTPBasicAuth()
db = SQLAlchemy(app)

def hash_password(password: str):
    return binascii.hexlify(hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                            app.config['SECURITY_PASSWORD_SALT'].encode('utf-8'), 1024)).decode('utf-8')

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id')))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    def verify_password(self, password: str) -> bool:
        return self.password_hash == hash_password(password)

    def generate_auth_token(self, expiration: int = 600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
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
        return User.query.get(data['id'])

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40))
    description = db.Column(db.String(255))

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@auth.get_user_roles
def get_user_roles(_):
    return list(map(lambda role: role.name, g.user.roles))

@app.route('/api/users', methods=['POST'])
def new_user():
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
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})

@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})

@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})

@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

@app.route('/api/resource-critical')
@auth.login_required(role=['admin', 'supporter'])
def get_resource_critical():
    return jsonify({'data': '(Critical) Hello, %s!' % g.user.username})

if __name__ == '__main__':
    if not os.path.exists(DATABASE_FILE_NAME):
        db.create_all()
        db.session.add(Role(name='admin'))
        db.session.add(Role(name='supporter'))
        db.session.add(Role(name='user'))
        db.session.commit()
    app.run(host='0.0.0.0', port='8080')
