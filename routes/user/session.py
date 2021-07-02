import api
import models.user as models_user
import models.session as models_session
import api_resp
import tools
import security
from flask import Blueprint, request, g

routes_user_session = Blueprint('routes_user_session', __name__)

@routes_user_session.route('/api/create-session', methods=['POST'])
def create_session():
    username, password = request.json.get('username'), request.json.get('password')
    if username is None or password is None:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.MISSING_ARGS, 400)  # missing arguments
    user = models_user.User.query.filter_by(username=username).first()
    if not user:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ACCOUNT_NOT_FOUND, 400)  # user not found
    if not user.verify_password(password):
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.INVALID_PASSWORD, 401)  # invalid password
    # check ban
    if user.temp_ban:
        if user.temp_ban.is_active():
            # account temporary banned
            return api_resp.APIResp.build_error_resp(api_resp.APIResp.ACCOUNT_TEMP_BAN, 401, {
                'reason': user.temp_ban.reason,
                'expires_in': user.temp_ban.get_left()
            })
    if user.perma_ban:
        # account permanently banned
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ACCOUNT_PERMA_BAN, 401, {
            'reason': user.perma_ban.reason
        })
    now = tools.timestamp()
    session = models_session.Session(
        user_id=user.id,
        expire_timestamp_usage=now + api.SESSION_USAGE_EXPIRES_IN,
        expire_timestamp_refresh=now + api.SESSION_REFRESH_EXPIRES_IN
    )
    api.db.session.add(session)
    api.db.session.commit()
    token = session.generate_auth_token()
    return api_resp.APIResp.build_resp(200, {'authorization': 'Bearer ' + token.decode('utf-8')})

@routes_user_session.route('/api/refresh-session', methods=['POST'])
@security.session_required()
def refresh_session():
    api.db.session.delete(g.session)
    now = tools.timestamp()
    session = models_session.Session(
        user_id=g.user.id,
        expire_timestamp_usage=now + api.SESSION_USAGE_EXPIRES_IN,
        expire_timestamp_refresh=now + api.SESSION_REFRESH_EXPIRES_IN
    )
    api.db.session.add(session)
    api.db.session.commit()
    token = session.generate_auth_token()
    return api_resp.APIResp.build_resp(200, {'authorization': 'Bearer ' + token.decode('utf-8')})

@routes_user_session.route('/api/invalidate-session', methods=['POST'])
@security.session_required()
def invalidate_session():
    api.db.session.delete(g.session)
    api.db.session.commit()
    return api_resp.APIResp.build_resp()

@routes_user_session.route('/api/invalidate-sessions', methods=['POST'])
@security.session_required()
def invalidate_sessions():
    sessions = models_session.Session.query.filter_by(user_id=g.user.id).all()
    for session in sessions:
        api.db.session.delete(session)
    api.db.session.commit()
    return api_resp.APIResp.build_resp()
