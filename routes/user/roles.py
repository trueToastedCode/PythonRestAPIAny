import api
import models.user as models_user
import security
import api_resp
from flask import Blueprint, request

routes_user_roles = Blueprint('routes_user_roles', __name__)

@routes_user_roles.route('/api/upgrade-user-role', methods=['POST'])
@security.session_required(roles=[models_user.Roles.ADMIN])
def upgrade_user_role():
    username, role = request.json.get('username'), request.json.get('role')
    if username is None or role is None:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.MISSING_ARGS, 400)  # missing arguments
    user = models_user.User.query.filter_by(username=username).first()
    if not user:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ACCOUNT_NOT_FOUND, 400)  # user not found
    role = models_user.Role.query.filter_by(name=role).first()
    if not role:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ROLE_NOT_FOUND, 400)  # role not found
    if role in user.roles:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ROLE_ALREADY_SET, 400)  # role already present
    user.roles.append(role)
    api.db.session.commit()
    return api_resp.APIResp.build_resp()

@routes_user_roles.route('/api/downgrade-user-role', methods=['POST'])
@security.session_required(roles=[models_user.Roles.ADMIN])
def downgrade_user():
    username, role = request.json.get('username'), request.json.get('role')
    if username is None or role is None:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.MISSING_ARGS, 400)  # missing arguments
    user = models_user.User.query.filter_by(username=username).first()
    if not user:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ACCOUNT_NOT_FOUND, 400)  # user not found
    role = models_user.Role.query.filter_by(name=role).first()
    if not role:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ROLE_NOT_FOUND, 400)  # role not found
    if not (role in user.roles):
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ROLE_NOT_SET, 400)  # role not set yet
    user.roles.remove(role)
    api.db.session.commit()
    return api_resp.APIResp.build_resp()
