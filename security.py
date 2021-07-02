import api
import binascii
import hashlib
import re
from flask import request, g
import models.session as models_session
import models.user as models_user
import api_resp

def hash_password(password: str) -> str:
    return binascii.hexlify(hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                            api.app.config['SECURITY_PASSWORD_SALT'].encode('utf-8'), 1024)).decode('utf-8')

RE_AUTH_HEADER = re.compile('Bearer\s\S+')

def session_required(roles=None):
    def decorator(function):
        def wrapper(*args, **kwargs):
            # check token
            token = request.headers.get('Authorization')
            if not token:
                return api_resp.APIResp.build_error_resp(api_resp.APIResp.TOKEN_MISSING, 401)  # token is missing
            if not RE_AUTH_HEADER.match(token):
                return api_resp.APIResp.build_error_resp(api_resp.APIResp.INVALID_TOKEN, 401)  # token is invalid
            # check session
            try:
                session = models_session.Session.verify_auth_token(token[7:])
            except models_session.Session.RefreshPendingError:
                return api_resp.APIResp.build_error_resp(api_resp.APIResp.TOKEN_NEEDS_REFRESH, 401)  # session needs refresh
            if not session:
                return api_resp.APIResp.build_error_resp(api_resp.APIResp.INVALID_SESSION, 401)  # invalid session
            user = models_user.User.query.get(session.user_id)
            # check ban
            if user.perma_ban:
                # account permanently banned
                return api_resp.APIResp.build_error_resp(api_resp.APIResp.ACCOUNT_PERMA_BAN, 401, {
                    'reason': user.perma_ban.reason
                })
            if user.temp_ban:
                if user.temp_ban.is_active():
                    # account temporary banned
                    return api_resp.APIResp.build_error_resp(api_resp.APIResp.ACCOUNT_TEMP_BAN, 401, {
                        'reason': user.temp_ban.reason,
                        'expires_in': user.temp_ban.get_left()
                    })
            # check roles
            if roles:
                user_roles = list(map(lambda user_role: user_role.name, user.roles))
                role_existent = False
                for role in roles:
                    if role in user_roles:
                        role_existent = True
                        break
                if not role_existent:
                    return api_resp.APIResp.build_error_resp(api_resp.APIResp.MISSING_ROLE, 401)  # missing role
            g.session = session
            g.user = user
            return function(*args, **kwargs)
        wrapper.__name__ = function.__name__
        return wrapper
    return decorator
