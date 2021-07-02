import api
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
import tools

class Session(api.db.Model):
    class RefreshPendingError(Exception):
        pass

    id = api.db.Column(api.db.Integer, primary_key=True)
    user_id = api.db.Column(api.db.Integer, api.db.ForeignKey('user.id'), nullable=False)
    expire_timestamp_usage = api.db.Column(api.db.Integer, nullable=False)  # valid period for usage
    expire_timestamp_refresh = api.db.Column(api.db.Integer, nullable=False)  # valid period for refresh after usage

    def generate_auth_token(self):
        s = Serializer(api.app.config['SECRET_KEY'], expires_in=self.expire_timestamp_refresh - tools.timestamp())
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token: str):
        s = Serializer(api.app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        session = Session.query.get(data['id'])
        if not session:
            return None  # session not found
        if tools.timestamp() > session.expire_timestamp_usage:
            raise Session.RefreshPendingError  # refresh is needed
        return session
