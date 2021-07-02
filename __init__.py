from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

DATABASE_FILE_NAME = 'db.sqlite3'

SESSION_USAGE_EXPIRES_IN = 60*180        # 180 min
SESSION_REFRESH_EXPIRES_IN = 60*60*24*7  # 1 week

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '0190736d4746be24da347263cc057503'
    app.config['SECURITY_PASSWORD_SALT'] = 'fa0de3aa1e2a8f67a7dcd1f93e2ac0ca'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DATABASE_FILE_NAME

    db.init_app(app)
    Migrate(app, db)

    # importing the models to make sure they are known to Flask-Migrate
    import models.session
    import models.user

    # any other registrations; blueprints, template utilities, commands

    return app
