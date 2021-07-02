import api
import models.user as models_user
import security
import api_resp
from flask import Blueprint, request

routes_user = Blueprint('routes_user', __name__)

@routes_user.route('/api/create-user', methods=['POST'])
def create_user():
    username, password = request.json.get('username'), request.json.get('password')
    if username is None or password is None:
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.MISSING_ARGS, 400)  # missing arguments
    if models_user.User.query.filter_by(username=username).first():
        return api_resp.APIResp.build_error_resp(api_resp.APIResp.ACCOUNT_ALREADY_EXISTS, 400)  # existing user
    role = models_user.Role.query.filter_by(name=models_user.Roles.USER).first()
    user = models_user.User(username=username, password_hash=security.hash_password(password), roles=[role])
    api.db.session.add(user)
    api.db.session.commit()
    return api_resp.APIResp.build_resp(201)
