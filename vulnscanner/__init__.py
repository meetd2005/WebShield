from flask import Flask, render_template, flash, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
import bcrypt
import os


# Import the db and app instances from the main app
from app import app, db, login_manager

# Import all the models and routes to register them
from vulnscanner.models import User, Scan, Report

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import after user_loader is defined to avoid circular imports
from vulnscanner.scanner import SecurityScanner
from vulnscanner.report_generator import ReportGenerator
from vulnscanner.routes import *  # This will register all the routes

# Set up the scanning tools
scanner = SecurityScanner()
report_generator = ReportGenerator()