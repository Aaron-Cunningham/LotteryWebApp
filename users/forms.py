import re

import pyotp
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo, Length

# Password validators
def character_check(form, field):
    # Excludes these chars
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_chars:
            # Shows the user which char isn't allowed
            raise ValidationError(f"Character {char} is not allowed.")


def phone_check(form, field):
    # Only allows ****-***-**** for a phone number format
    p = re.compile('\d{4}-\d{3}-\d{4}')
    if not p.match(field.data):
        # If entered number in wrong show this message
        raise ValidationError("Phone number must be in this format XXXX-XXX-XXXX (including the dashes)")


def password_check(form, field):
    # Regular expression restricting what needs to be in password
    p = re.compile(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d])')
    if not p.match(field.data):
        # If format doesn't match show message
        raise ValidationError(
            "Password must contain 1 digit, 1 lowercase letter, 1 uppercase letter and, 1 special character, and 6-12 characters in length")


def postcode_check(form, field):
    # Restricts the format of the post codes
    x = re.compile('[A-Za-z]\d\s\d[A-Za-z][A-Za-z]')
    y = re.compile('[A-Za-z]\d\d\s\d[A-Za-z][A-Za-z]')
    z = re.compile('[A-Za-z][A-Za-z]\d\s\d[A-Za-z][A-Za-z]')

    if not (x.match(field.data) or y.match(field.data) or z.match(field.data)):
        # If format doesn't match show message
        raise ValidationError(
            "Postcode should be in these formats. (X: LETTERS Y: DIGITS with spaces) *XY YXX* *XYY YXX* *XXY YXX*")


def year_check(form, field):
    # Restricts the format of the date of birth
    x = re.compile('\d{2}/\d{2}/\d{4}')
    if not x.match(field.data):
        # If format doesn't match show message
        raise ValidationError("Error in date of birth should be in this format DD/MM/YYYY")

# Creates the form fields and validators for register form
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    firstname = StringField('First name', validators=[DataRequired(), character_check])
    lastname = StringField('Last name', validators=[DataRequired(), character_check])
    phone = StringField('Phone number', validators=[DataRequired(), phone_check])
    password = PasswordField('Password', validators=[DataRequired(), password_check, Length(min=6, max=12)])
    confirm_password = PasswordField('Confirm password', validators=[DataRequired(), Length(min=6, max=12), EqualTo('password', message='Passwords must match')])
    date_of_birth = StringField('Date of Birth', validators=[DataRequired(), year_check])
    post_code = StringField('Post Code', validators=[DataRequired(), postcode_check])
    submit = SubmitField()

# Creates the form fields and validators for login form
class LoginForm(FlaskForm):

    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    pin = StringField('Pin', validators=[DataRequired(), Length(min=6, max=6, message="Pin must be 6 digits")])
    postcode = StringField('Post Code', validators=[DataRequired(), postcode_check])
    recaptcha = RecaptchaField()
    submit = SubmitField()

# Creates the form fields and validators for password form
class PasswordForm(FlaskForm):
    current_password = PasswordField(id='password', validators=[DataRequired()])
    show_password = BooleanField('Show password', id='check')
    new_password = PasswordField(validators=[DataRequired(), Length(min=6, max=12), password_check])
    confirm_new_password = PasswordField(validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Change Password')
