from pathlib import Path
from flask import Flask, render_template, flash, get_flashed_messages, redirect, url_for,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from flask_login import UserMixin, LoginManager, login_manager, login_required, login_user, logout_user, current_user
from flask import request
# Set up the app and database
app = Flask(__name__)


# Absolute path to the database
BASE_DIR = Path(__file__).resolve().parent
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{BASE_DIR / 'report.db'}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '264f2a3281e9bdd4ffd09fab'
app.config['SQLALCHEMY_ECHO'] = False
db=SQLAlchemy(app)
app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


from vulnscanner import routes


