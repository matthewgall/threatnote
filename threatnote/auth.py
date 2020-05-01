from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from models import User, Organization
from config import db
from sqlalchemy import func
import os
import binascii

auth = Blueprint('auth', __name__)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login')) # if user doesn't exist or password is wrong, reload the page

    login_user(user)

    # if the above check passes, then we know the user has the right credentials
    # indicators = db.session.query(func.count(Indicators.id)).scalar()
    # reports = db.session.query(func.count(Reports.id)).scalar()
    # intel_reqs = db.session.query(func.count(Requirements.id)).scalar()
    if user.new_user:
        return redirect(url_for('welcome'))        
    else:
        return redirect(url_for('homepage'))

# @auth.route('/signup', methods=['POST'])
# def signup_post():
#     name = request.form.get('name')

#     email = request.form.get('email')
#     password = request.form.get('password')
#     org_key = request.form.get('org_key')

#     user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

#     if user: # if a user is found, we want to redirect back to signup page so user can try again
#         flash('Email address already exists')
#         return redirect(url_for('auth.signup'))
#     if not org_key:
#         flash('Enter organization key')
#         return redirect(url_for('auth.signup'))
#     org= Organization.query.filter_by(org_key = org_key).first()
#     if not org:
#         flash('Invalid organization key')
#         return redirect(url_for('auth.signup'))
    
#     api_key = binascii.b2a_hex(os.urandom(16)).decode()
#     if not name:
#         name = request.form.get('email').split("@")[0]
#     # create new user with the form data. Hash the password so plaintext version isn't saved.
#     new_user = User(email=email, password=generate_password_hash(password, method='sha256'),
#                     vt_api_key='',
#                     organization=org.id,
#                     tn_api_key=api_key, 
#                     name=name, 
#                     role='User')

#     # add the new user to the database
#     db.session.add(new_user)
#     db.session.commit()

#     return redirect(url_for('auth.login'))

