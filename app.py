# IMPORTS
import logging
import os
from functools import wraps

from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_qrcode import QRcode

# CONFIG
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lottery.db'
app.config['SQLALCHEMY_ECHO'] = os.getenv('SQLALCHEMY_ECHO') == True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == True
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')
# initialise database
db = SQLAlchemy(app)
qrcode = QRcode(app)


# Logging
class SecurityFilter(logging.Filter):
    def filter(self, record):
        return 'SECURITY' in record.getMessage()


file_handler = logging.FileHandler('lottery.log', 'a')
file_handler.setLevel(logging.WARNING)
file_handler.addFilter(SecurityFilter())
formatter = logging.Formatter('%(asctime)s : %(message)s', '%m/%d/%Y %I:%M:%S %p')
file_handler.setFormatter(formatter)

logger = logging.getLogger()
logger.addHandler(file_handler)


# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


# Role checking
def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                # Sends a log to the log file if there was an unauthorised access attempts
                logging.warning('SECURITY - Unauthorised Access Attempts [%s, %s, %s, %s]', current_user.id,
                                current_user.email, current_user.role, request.remote_addr)
                return render_template('errors/403.html')
            return f(*args, **kwargs)

        return wrapped

    return wrapper


# BLUEPRINTS
# import blueprints
from users.views import users_blueprint
from admin.views import admin_blueprint
from lottery.views import lottery_blueprint

#
# # register blueprints with app
app.register_blueprint(users_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(lottery_blueprint)

# Login manager
login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.init_app(app)

from models import User


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.errorhandler(400)
def internal_error(error):
    return render_template('errors/400.html'), 400


@app.errorhandler(403)
def internal_error(error):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def internal_error(error):
    return render_template('errors/500.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/404.html'), 500


@app.errorhandler(503)
def internal_error(error):
    return render_template('errors/404.html'), 503


if __name__ == "__main__":
    app.run()
