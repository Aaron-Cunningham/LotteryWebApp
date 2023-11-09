import bcrypt
import pyotp
from flask import request
from cryptography.fernet import Fernet
from app import db, app
from flask_login import UserMixin
from datetime import datetime

# Method used to encrypt the lottery_key
def encrypt(data, lottery_key):
    return Fernet(lottery_key).encrypt(bytes(data, 'utf-8'))

# Method to decrypt the lottery_key
def decrypt(data, lottery_key):
    return Fernet(lottery_key).decrypt(data).decode('utf-8')


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(10000), nullable=False)
    pin_key = db.Column(db.String(32), nullable=False, default=pyotp.random_base32())
    lottery_key = db.Column(db.BLOB, nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False, default='user')
    postcode = db.Column(db.String(100), nullable=False)
    dateofbirth = db.Column(db.String(100), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    current_login = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    current_ip_login = db.Column(db.String(100), nullable=True)
    last_ip_login = db.Column(db.String(100), nullable=True)
    successful_logins = db.Column(db.Integer, nullable=True, default=0)

    # Define the relationship to Draw
    draws = db.relationship('Draw')

    def __init__(self, email, firstname, lastname, phone, password, dateofbirth, postcode, role, pin_key):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.role = role
        self.dateofbirth = dateofbirth
        self.postcode = postcode
        self.pin_key = pin_key
        self.registered_on = datetime.now()
        self.current_login = None
        self.last_login = None
        self.last_ip_login = None
        self.current_ip_login = None
        self.successful_logins = None
        self.lottery_key = Fernet.generate_key()

    # Verifies the password is correct
    def verify_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password)

    # Used to log in by checking postcode entered is the same stored in Database
    def verify_postcode(self, postcode):
        return self.postcode == postcode

    # Verifies the pin the user inputs and compares to pin_key
    def verify_pin(self, pin):
        return pyotp.TOTP(self.pin_key).verify(pin)

    #
    def get_2fa_uri(self):
        return str(pyotp.totp.TOTP(self.pin_key).provisioning_uri(
            name=self.email,
            issuer_name='CSC2031 Blog')
        )


class Draw(db.Model):
    __tablename__ = 'draws'

    id = db.Column(db.Integer, primary_key=True)

    # ID of user who submitted draw
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

    # 6 draw numbers submitted
    numbers = db.Column(db.String(100), nullable=False)

    # Draw has already been played (can only play draw once)
    been_played = db.Column(db.BOOLEAN, nullable=False, default=False)

    # Draw matches with master draw created by admin (True = draw is a winner)
    matches_master = db.Column(db.BOOLEAN, nullable=False, default=False)

    # True = draw is master draw created by admin. User draws are matched to master draw
    master_draw = db.Column(db.BOOLEAN, nullable=False)

    # Lottery round that draw is used
    lottery_round = db.Column(db.Integer, nullable=False, default=0)

    def __init__(self, user_id, numbers, master_draw, lottery_round, lottery_key):
        self.user_id = user_id
        # Encrypts the numbers on initilisation
        self.numbers = encrypt(numbers, lottery_key)
        self.been_played = False
        self.matches_master = False
        self.master_draw = master_draw
        self.lottery_round = lottery_round

    # This will decrypt the numbers
    def view_numbers(self, lottery_key):
        self.numbers = decrypt(self.numbers, lottery_key)


def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(email='admin@email.com',
                     password='Admin1!',
                     pin_key='BFB5S34STBLZCOB22K6PPYDCMZMH46OJ',
                     firstname='Alice',
                     lastname='Jones',
                     phone='0191-123-4567',
                     role='admin',
                     dateofbirth='01/01/1999',
                     postcode='NE4 5SA')

        user1 = User(email='test@test.com',
                     password='Test1234!',
                     pin_key='IXE547QYEYRNDHO5TZD7RBM67ONEDJDC',
                     firstname='Aaron',
                     lastname='Cunningham',
                     phone='4444-444-4444',
                     role='user',
                     dateofbirth='29/01/1999',
                     postcode='NE4 5SA')

        db.session.add(admin)
        db.session.add(user1)
        db.session.commit()
