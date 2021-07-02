from __init__ import *
import routes.user.user as routes_user
import routes.user.roles as routes_user_roles
import routes.user.session as routes_user_session
import routes.user.ban as routes_user_ban
import models.user as models_user
import security
import os

app = create_app()

if __name__ == '__main__':
    if not os.path.exists(DATABASE_FILE_NAME):
        # create clean database
        with app.app_context():
            db.create_all()
            role_admin = models_user.Role(name=models_user.Roles.ADMIN, description=models_user.Roles.ADMIN_DESC)
            db.session.add(role_admin)
            db.session.add(models_user.Role(name=models_user.Roles.SUPPORTER, description=models_user.Roles.SUPPORTER_DESC))
            db.session.add(models_user.Role(name=models_user.Roles.USER, description=models_user.Roles.USER_DESC))
            db.session.add(models_user.User(
                username='admin',
                password_hash=security.hash_password('admin'),
                roles=[role_admin]
            ))
            db.session.commit()
    app.register_blueprint(routes_user.routes_user)
    app.register_blueprint(routes_user_roles.routes_user_roles)
    app.register_blueprint(routes_user_session.routes_user_session)
    app.register_blueprint(routes_user_ban.routes_user_ban)
    app.run()
