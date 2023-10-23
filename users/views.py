# IMPORTS
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session
from flask_login import login_user, current_user, logout_user, login_required
from markupsafe import Markup

from app import db, requires_roles
from models import User
from users.forms import RegisterForm, LoginForm, PasswordForm

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # Prevents users already registered and logged in from accessing
    if current_user.is_authenticated:
        flash("This account is already registered")
        return redirect(url_for('lottery.lottery'))
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        postcode=form.post_code.data,
                        dateofbirth=form.date_of_birth.data,
                        pin_key=pyotp.random_base32(),
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        # sends user to login page
        session['email'] = new_user.email
        return redirect(url_for('users.setup_2fa'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    # Prevents users already logged in from accessing
    if current_user.is_authenticated:
        flash("This account is already logged in")
        return redirect(url_for('lottery.lottery'))
    form = LoginForm()

    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user or not user.verify_password(form.password.data) or not user.verify_pin(form.pin.data):
            session['authentication_attempts']+=1
            if session.get('authentication_attempts') >=3:
                flash(Markup('Number of incorrect login attempts exceeded. Please click <a href="/reset">here</a> to reset.'))
                return render_template('users/login.html')
            flash('Please check your login details and try again, {} login attempts remaining'.format(3 - session.get('authentication_attempts')))
            return render_template('users/login.html', form=form)
        else:
            login_user(user)
            if current_user.role == 'user':
                return redirect(url_for('lottery.lottery'))
            elif current_user.role == 'admin':
                return redirect(url_for('admin.admin'))

    return render_template('users/login.html', form=form)

@users_blueprint.route('/setup_2fa')
def setup_2fa():
    if 'email' not in session:
        return redirect(url_for('users.register'))
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('users.register'))
    del session['email']
    return render_template('users/setup_2fa.html', email=user.email, uri=user.get_2fa_uri()), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }



# view user profile
@users_blueprint.route('/profile')
def profile():
    return render_template('users/profile.html', name="PLACEHOLDER FOR FIRSTNAME")


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)

@users_blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('main/index.html')


@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


@users_blueprint.route('/update_password', methods=['GET', 'POST'])
@login_required
@requires_roles('user')
def update_password():
    form = PasswordForm()
    if form.validate_on_submit():
        if not current_user.verify_password(form.current_password.data):
            flash("Current password is incorrect")
        elif current_user.verify_password(form.new_password.data):
            flash("New password cant be the same as the old password")
        else:
            current_user.password = form.new_password.data
            db.session.commit()
            flash("Password changed successfully")
            return redirect(url_for('users.account'))

    return render_template('users/update_password.html', form=form)


