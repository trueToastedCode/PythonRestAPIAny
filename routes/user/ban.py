import api
import models.user as models_user
import security
import api_resp
import tools
from flask import Blueprint, request

routes_user_ban = Blueprint('routes_user_ban', __name__)

@routes_user_ban.route('/api/ban-user-temporary', methods=['POST', 'DELETE'])
@security.session_required(roles=[models_user.Roles.ADMIN, models_user.Roles.SUPPORTER])
def ban_user_temporary():
    username, seconds, reason = request.json.get('username'), request.json.get('seconds'), request.json.get('reason')
    if username is None or seconds is None or not reason:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.MISSING_ARGS, 400)  # missing arguments
    user = models_user.User.query.filter_by(username=username).first()
    if not user:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ACCOUNT_NOT_FOUND, 400)  # user not found
    if request.method == 'POST':
        temp_ban = models_user.TempBan(user_id=user.id, expire_timestamp=tools.timestamp() + int(seconds), reason=reason)
        user.temp_ban = temp_ban
    elif user.temp_ban:
        api.db.session.delete(user.temp_ban)
    else:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.CANT_DELETE_NO_BAN, 400)  # no ban active
    api.db.session.commit()
    return api_resp.APIResp.build_resp()

@routes_user_ban.route('/api/ban-user-permanent', methods=['POST', 'DELETE'])
@security.session_required(roles=[models_user.Roles.ADMIN, models_user.Roles.SUPPORTER])
def ban_user_permanent():
    username, reason = request.json.get('username'), request.json.get('reason')
    if username is None or reason is None:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.MISSING_ARGS, 400)  # missing arguments
    user = models_user.User.query.filter_by(username=username).first()
    if not user:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ACCOUNT_NOT_FOUND, 400)  # user not found
    if request.method == 'POST':
        perma_ban = models_user.PermaBan(user_id=user.id, reason=reason)
        user.perma_ban = perma_ban
    elif user.perma_ban:
        api.db.session.delete(user.perma_ban)
    else:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.CANT_DELETE_NO_BAN, 400)  # no ban active
    api.db.session.commit()
    return api_resp.APIResp.build_resp()
