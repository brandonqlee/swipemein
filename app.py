# import os
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_sqlalchemy import SQLAlchemy, sqlalchemy
from wtforms import Form, StringField, SelectField, PasswordField, IntegerField, DateField, SubmitField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import datetime
import pytz
from werkzeug.datastructures import MultiDict

app = Flask(__name__)
# app.config.from_object(os.environ['APP_SETTINGS'])
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:vhTmCm0314)#!$@localhost/swipe-me-in'

db = SQLAlchemy(app)

# Create database model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), unique=False, nullable=False)
    last_name = db.Column(db.String(20), unique=False, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(), unique=False, nullable=False)
    has_swipes = db.Column(db.Boolean, unique=False, nullable=False)
    time_registered = db.Column(db.DateTime, unique=False, nullable=False)

    def __init__(self, first_name, last_name, email, password, has_swipes, time_registered):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password
        self.has_swipes = has_swipes
        self.time_registered = time_registered

    def __repr__(self):
        return '<User %r>' % self.email

# db.create_all()
# db.session.commit()

# erica = User('Erica', 'Li', 'b@email.com', 'pw', True, datetime.datetime.today())
#
# db.session.add(erica)
# db.session.commit()
# c = User.query.all()
# print(c)

@app.route('/')
def index():
    return render_template('index.html')

class RegisterForm(Form):
    first_name = StringField('First name', [
        validators.DataRequired(),
        validators.Length(min=1, max=20)
    ])
    last_name = StringField('Last name', [
        validators.DataRequired(),
        validators.Length(min=1, max=20)
    ])
    has_swipes = SelectField(
            'Do you have meals to spare?',
            choices=[('true', 'Have meals to spare'), ('false', 'Need meals to survive')]
        )
    email = StringField('Email', [
        validators.DataRequired(),
        validators.Length(min=6, max=50),
        validators.Email(message = 'Please enter a valid email.')
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)

    if request.method == 'POST' and form.validate():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = sha256_crypt.hash(form.password.data) # encrypt password
        if form.has_swipes.data == 'true':
            has_swipes = True
        else:
            has_swipes = False

        new_user = User(first_name, last_name, email, password, has_swipes, datetime.datetime.today())

        try:
            # Add new user to db
            db.session.add(new_user)
            db.session.commit()
            # Sucessfully added new user to db, redirect to login
            flash('You are now registered and can log in.', 'success')
            return redirect(url_for('login'))
        except sqlalchemy.exc.IntegrityError as error:
            flash('That email is already registered in the system, please log in.', 'danger')
            return render_template('register.html', form=form)
        # Catch other server exceptions
        except Exception as error:
            flash('Server is busy, please try again later.', 'danger')
            return render_template('register.html', form=form)
    # GET method
    else:
        return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form fields
        email = request.form['email']
        password_candidate = request.form['password']

        current_user = User.query.filter_by(email=email).first()

        # Check if user with email is found in db
        if current_user != None:
            # Compare passwords to see if they match
            if sha256_crypt.verify(password_candidate, current_user.password):
                # Username and password matched!
                session['logged_in'] = True

                session['first_name'] = current_user.first_name
                session['last_name'] = current_user.last_name
                session['email'] = current_user.email
                session['has_swipes'] = current_user.has_swipes

                flash('You are now logged in.', 'success')
                if session['has_swipes']:
                    return redirect(url_for('feed_shareMeal'))
                else:
                    return redirect(url_for('eat_explore'))
            else:
                # User found but password incorrect
                error = 'Please check your password and try again.'
                return render_template('login.html', error = error)
        else:
            # User not found
            error = 'Unrecognized email, please try again.'
            return render_template('login.html', error = error)
    # GET method
    else:
        return render_template('login.html')

# first page for donater
@app.route('/feed_shareMeal')
def feed_shareMeal():
    return render_template('feed_shareMeal.html')

# first page for receiver
@app.route('/eat_explore')
def eat_explore():
    return render_template('eat_explore.html')

if __name__ == '__main__':
    app.secret_key = 'teamc4ever'
    app.run(debug=True)
