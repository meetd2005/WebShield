from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length,EqualTo, ValidationError
from vulnscanner.models import User
from werkzeug.security import check_password_hash



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=20)])# or you can use BooleanField for checkboxes
    submit = SubmitField('Sign In')
    

    
# Define the Registration Form
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(),EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        existing_user_username=User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")