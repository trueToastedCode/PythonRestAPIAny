import json
from flask import Response

class APIResp:
    # requests: 1
    OK = 0
    MISSING_ARGS = 1, 'Arguments are missing'
    INVALID_DATA = 2, 'Invalid data'

    # security: 1000
    TOKEN_MISSING = 1000, 'The Authorization token has not been found'
    INVALID_TOKEN = 1001, 'The Authorization token has an invalid syntax'
    INVALID_SESSION = 1002, 'The session could not have been validated'
    TOKEN_NEEDS_REFRESH = 1003, 'The token needs to be refreshed'
    MISSING_ROLE = 1004, 'The account misses on permission'
    INVALID_PASSWORD = 1005, 'The password is invalid'

    # account: 2000
    ACCOUNT_ALREADY_EXISTS = 2000, 'Account with the chosen username already exists'
    ACCOUNT_NOT_FOUND = 2001, 'Account could not be found'
    ACCOUNT_TEMP_BAN = 2002, 'Account has been temporary banned'
    ACCOUNT_PERMA_BAN = 2003, 'Account has been permanently banned'
    ROLE_NOT_FOUND = 2004, 'Role could not be found'
    ROLE_ALREADY_SET = 2005, 'Role is already present'
    ROLE_NOT_SET = 2006, 'Role has not been set yet'
    CANT_DELETE_NO_BAN = 2007, 'Cannot remove a ban that is not present'

    @staticmethod
    def build_str(additional: dict = None) -> str:
        d = {'status': APIResp.OK}
        if additional:
            d.update(additional)
        return json.dumps(d)

    @staticmethod
    def build_error_str(error, additional: dict = None) -> str:
        d = {'status': error[0], 'message': error[1]}
        if additional:
            d.update(additional)
        return json.dumps(d)

    @staticmethod
    def build_resp(status: int = 200, additional: dict = None) -> Response:
        return Response(APIResp.build_str(additional), status=status, mimetype='application/json')

    @staticmethod
    def build_error_resp(error, status: int = 400, additional: dict = None) -> Response:
        return Response(APIResp.build_error_str(error, additional), status=status, mimetype='application/json')
