import api
import security
import tools

class Roles:
    ADMIN = 'admin'
    ADMIN_DESC = 'Fixes problems and changes critical data'

    SUPPORTER = 'supporter'
    SUPPORTER_DESC = 'Supports users and communicates to admins'

    USER = 'user'
    USER_DESC = 'Regular user operating his account'

roles_users = api.db.Table('roles_users',
    api.db.Column('user_id', api.db.Integer, api.db.ForeignKey('user.id')),
    api.db.Column('role_id', api.db.Integer, api.db.ForeignKey('role.id')))

class User(api.db.Model):
    id = api.db.Column(api.db.Integer, primary_key=True)
    username = api.db.Column(api.db.String(32), nullable=False)
    password_hash = api.db.Column(api.db.String(128), nullable=False)
    sessions = api.db.relationship('Session', backref='owner')
    roles = api.db.relationship('Role', secondary=roles_users, backref=api.db.backref('users', lazy='dynamic'))
    temp_ban = api.db.relationship("TempBan", backref='owner', uselist=False)
    perma_ban = api.db.relationship("PermaBan", backref='owner', uselist=False)

    def verify_password(self, password: str) -> bool:
        return self.password_hash == security.hash_password(password)

    def get_role_names(self) -> list:
        return list(map(lambda role: role.name, self.roles))

class Role(api.db.Model):
    id = api.db.Column(api.db.Integer, primary_key=True)
    name = api.db.Column(api.db.String(40), nullable=False)
    description = api.db.Column(api.db.String(255))

class TempBan(api.db.Model):
    id = api.db.Column(api.db.Integer, primary_key=True)
    user_id = api.db.Column(api.db.Integer, api.db.ForeignKey('user.id'))
    expire_timestamp = api.db.Column(api.db.Integer, nullable=False)
    reason = api.db.Column(api.db.String(255), nullable=False)

    def is_active(self) -> bool:
        return self.expire_timestamp > tools.timestamp()

    def get_left(self) -> int:
        return self.expire_timestamp - tools.timestamp() if self.is_active() else 0

class PermaBan(api.db.Model):
    id = api.db.Column(api.db.Integer, primary_key=True)
    user_id = api.db.Column(api.db.Integer, api.db.ForeignKey('user.id'))
    reason = api.db.Column(api.db.String(255), nullable=False)
