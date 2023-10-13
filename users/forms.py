import re
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo, Length


def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(f"Character {char} is not allowed.")


def phone_check(form, field):
    p = re.compile('\d{4}-\d{3}-\d{4}')
    if not p.match(field.data):
        raise ValidationError("Phone number must be in this format XXXX-XXX-XXXX (including the dashes)")


def password_check(form, field):
    p = re.compile(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d])')
    if not p.match(field.data):
        raise ValidationError(
            "Password must contain 1 digit, 1 lowercase letter, 1 uppercase letter and, 1 special character")


def postcode_check(form, field):
    x = re.compile('[A-Za-z]\d\s\d[A-Za-z][A-Za-z]')
    y = re.compile('[A-Za-z]\d\d\s\d[A-Za-z][A-Za-z]')
    z = re.compile('[A-Za-z][A-Za-z]\d\s\d[A-Za-z][A-Za-z]')

    if not (x.match(field.data) or y.match(field.data) or z.match(field.data)):
        raise ValidationError("Postcode should be in these formats. (X: LETTERS Y: DIGITS with spaces) *XY YXX* *XYY YXX* *XXY YXX*")



def year_check(form, field):
    x = re.compile('\d{2}/\d{2}/\d{4}')
    if not x.match(field.data):
        raise ValidationError("Error in date of birth should be in this format DD/MM/YYYY")
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    firstname = StringField('First name', validators=[DataRequired(), character_check])
    lastname = StringField('Last name', validators=[DataRequired(), character_check])
    phone = StringField('Phone number', validators=[DataRequired(), phone_check])
    password = PasswordField('Password', validators=[DataRequired(), password_check, Length(min=6, max=12)])
    confirm_password = PasswordField('Confirm password', validators=[DataRequired(), Length(min=6, max=12),
                                                                     EqualTo('password',
                                                                             message='Passwords must match')])
    date_of_birth = StringField('Date of Birth', validators=[DataRequired(), year_check])
    post_code = StringField('Post Code', validators=[DataRequired(), postcode_check])
    submit = SubmitField()
