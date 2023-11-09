# IMPORTS
import logging
import bcrypt
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import login_user, current_user, logout_user, login_required
from markupsafe import Markup
from datetime import datetime
from app import db, requires_roles
from models import User
from users.forms import RegisterForm, LoginForm, PasswordForm

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')



@users_blueprint.route('/admin_register', methods=['GET', 'POST'])
@login_required
@requires_roles('admin')
def admin_register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_admin = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        postcode=form.post_code.data,
                        dateofbirth=form.date_of_birth.data,
                        pin_key=pyotp.random_base32(),
                        role='admin')

        # add the new user to the database
        db.session.add(new_admin)
        db.session.commit()

        #Flashing a message to let the admin know a new admin has been added
        flash(Markup('New admin has been added to the system, authorisation set up manually'))
        # Logs when a user registered
        logging.warning('SECURITY - Admin Registered [%s, %s]', form.email.data, request.remote_addr)
        return redirect(url_for('admin.admin'))
        # Redirects so user can set up 2FA
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


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
        # Logs when a user registered
        logging.warning('SECURITY - User Registered [%s, %s]', form.email.data, request.remote_addr)
        session['email'] = new_user.email
        # Redirects so user can set up 2FA
        return redirect(url_for('users.setup_2fa'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    # Prevents users already logged in from accessing
    if current_user.is_authenticated:
        flash("This account is already logged in")
        # Returns back to lottery page
        return redirect(url_for('lottery.lottery'))
    form = LoginForm()

    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # Checks password and pin matches what's in the database
        if not user or not user.verify_password(form.password.data) or not user.verify_pin(form.pin.data) or not user.verify_postcode(form.postcode.data):
            # If incorrect data entered will add 1 to authentication attempts
            session['authentication_attempts'] += 1
            # Adds invalid login attempts to the log file
            logging.warning('SECURITY - Invalid login attempt [%s, %s]', form.email.data, request.remote_addr)
            # Sets max authentication attempts to 3
            if session.get('authentication_attempts') >= 3:
                # If user has more than 3 failed login attempts flash message with link to reset login attempts
                flash(Markup(
                    'Number of incorrect login attempts exceeded. Please click <a href="/reset">here</a> to reset.'))
                # Redirects to login page
                return render_template('users/login.html')
            # Flashes message with remaining login attempts
            flash('Please check your login details and try again, {} login attempts remaining'.format(
                3 - session.get('authentication_attempts')))
            return render_template('users/login.html', form=form)
        else:
            login_user(user)
            # Updates the users last and current log in
            current_user.last_login = current_user.current_login
            current_user.current_login = datetime.now()
            # Updates the users last and current ip used to log in
            current_user.last_ip_login = current_user.current_ip_login
            current_user.current_ip_login = request.remote_addr
            # Updates the total number of successful logins for the current user
            current_user.successful_logins += 1
            db.session.commit()
            # Logs when a user logged in
            logging.warning('SECURITY - User Login [%s, %s, %s]', current_user.id, current_user.email,
                            request.remote_addr)
            # If a normal user redirect to ltotery page
            if current_user.role == 'user':
                return redirect(url_for('lottery.lottery'))
            # If admin redirect to admin page
            elif current_user.role == 'admin':
                return redirect(url_for('admin.admin'))

    return render_template('users/login.html', form=form)


# Sets up 2FA for the user
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


# Logs out a user
@users_blueprint.route('/logout')
@login_required
def logout():
    # Logs when a user logs out
    logging.warning('SECURITY - User log out [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)

    logout_user()
    return render_template('main/index.html')


# Resets user login attempts
@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


# Used to update the users password
@users_blueprint.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    form = PasswordForm()
    if form.validate_on_submit():
        if not current_user.verify_password(form.current_password.data):
            flash("Current password is incorrect")
        elif current_user.verify_password(form.new_password.data):
            flash("New password cant be the same as the old password")
        else:
            # Hashes the updated password and updates it to current
            current_user.password = bcrypt.hashpw(form.new_password.data.encode('utf-8'), bcrypt.gensalt())
            # Commits change to database
            db.session.commit()
            flash("Password changed successfully")
            return redirect(url_for('users.account'))

    return render_template('users/update_password.html', form=form)
