import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)

# Configure the application
app.secret_key = os.environ.get("SESSION_SECRET", "your-secret-key-for-dev")

# Handle database URL configuration with error checking
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    print("Error: DATABASE_URL environment variable is not set", file=sys.stderr)
    sys.exit(1)

# Convert postgres:// to postgresql:// if necessary
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# Configure SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Create tables and import routes
with app.app_context():
    from vulnscanner import models, routes  # noqa: F401
    try:
        db.create_all()
        print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {e}", file=sys.stderr)
        sys.exit(1)