from flask import Flask, render_template, redirect, url_for, flash, jsonify, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_cors import CORS
from flask_wtf.recaptcha import RecaptchaField
from datetime import date
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, FreeSignalForm, VipSignalForm, ForgotForm, ResetForm, VerifyForm, EditForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
import os
import psycopg2
import requests
import pandas as pd
import re
import time
import json
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer
import random
import hashlib
import hmac
from datetime import datetime, timedelta
from pycoin import key
import eth_utils
from urllib.parse import urlsplit, urlunsplit
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'starisborn222@gmail.com'
app.config['MAIL_PASSWORD'] = 'bqcymvdzyinojjae'
app.config['MAIL_DEFAULT_SENDER'] = 'starisborn222@gmail.com'
app.config['UPLOAD_FOLDER'] = 'static/uploads'


#reCaptcha 
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LfM_Z0mAAAAAJKd74mklX60n8lfW4V4Bh3YkfYq'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LfM_Z0mAAAAALgUv1M87Ea6A1jaCCmmBr_WL6zk'
google_bp = make_google_blueprint(
    client_id="625561773264-fphgi6kk497dk7jm6bf8638cm80m38n6.apps.googleusercontent.com",
    client_secret="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",
    scope=["profile", "email"],
    redirect_to="google_login",
)

# Register the blueprint
app.register_blueprint(google_bp, url_prefix="/login")

mail = Mail(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
CORS(app,  origins=['https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest'], headers=['Content-Type'])

# api_key = 'rFSvLL1xr7PWB3HlpGSa9M33cS7jSojq7zZneO4GMzGMlTzVlUSZWPagI5qCElzS'
# api_secret = 'QYiAZwyuSKZ8f9dfwQRq5MdN0Qi21hHVUZgJoOTP7AoWqX4DxqSr0VMn2YVqNtlq'
# client = Client(api_key, api_secret)

ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating="g", default="retro", force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] =  "sqlite:///blog.db"
#postgres://blog:28TUl9nXzhdxkwWec7vJqS4lXrjmG9u8@dpg-chf0keu4dad1jq99ae80-a.oregon-postgres.render.com/blog_1ld7
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.app_context().push()

url = 'https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest'
headers = {'Accepts': 'application/json', 'X-CMC_PRO_API_KEY': 'aa05b939-ce70-4636-bc5b-5d81c9d9c300'}

    # Make the API call and retrieve the data
response = requests.get(url, headers=headers)
data = response.json()


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    username = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    reset_code = db.Column(db.Integer)
    admin_rights = db.Column(db.Boolean, default=False)

    posts = relationship("BlogPost", back_populates="author")
    subscriber = relationship("Subscribe", back_populates="sub_sender_user")
    comments = relationship("Comment", back_populates="comment_author")
    payments = relationship("Payment", back_populates="sender_user")
    payment = db.relationship("Payment", backref="user", uselist=False)

with app.app_context():
    db.create_all()

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(250), nullable=True)
    img_url = db.Column(db.String(250), nullable=False)
    clicks = db.Column(db.Integer, default=0)

    comments = relationship("Comment", back_populates="parent_post")

with app.app_context():
    db.create_all()

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    text = db.Column(db.Text, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
with app.app_context():
    db.create_all()

class FreeSignal(db.Model):
    __tablename__ = "freesignal"
    id = db.Column(db.Integer, primary_key=True)
    entry_point = db.Column(db.Integer)
    stop_loss = db.Column(db.Integer)
    take_profit = db.Column(db.Integer)
    coin_symbol = db.Column(db.String(100))
    date = db.Column(db.String(250), nullable=False)
with app.app_context():
    db.create_all()

class VipSignal(db.Model):
     __tablename__ = "vipsignal"
     id = db.Column(db.Integer, primary_key=True)
     entry_point = db.Column(db.Integer)
     stop_loss = db.Column(db.Integer)
     take_profit = db.Column(db.Integer)
     coin_symbol = db.Column(db.String(100))
     date = db.Column(db.String(250), nullable=False)
with app.app_context():
    db.create_all()

class Payment(db.Model):
    __tablename__ = 'payment'
    id = db.Column(db.Integer, primary_key=True)
    payment_status = db.Column(db.String(50))
    deposited_amount = db.Column(db.Float)
    withdrawal_amount = db.Column(db.Float)
    payment_id = db.Column(db.String(50))
    transaction_date = db.Column(db.String(250), nullable=False)

    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    sender_user = relationship("User", back_populates="payments")
with app.app_context():
    db.create_all()

# Define the Subscribe model
class Subscribe(db.Model):
    __tablename__ = "subscribe"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False)
    subscription_plan = db.Column(db.String(50))
    subscription_cost = db.Column(db.Float)
    subscription_duration = db.Column(db.Integer)
    sub_sender_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    sub_sender_user = relationship("User", back_populates="subscriber") 
    transactional_date = db.Column(db.String(250), nullable=False)
with app.app_context():
    db.create_all() 

class Admin(db.Model):
    __tablename__ = "admin"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
with app.app_context():
    db.create_all()

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and (current_user.id == 1 or current_user.admin_rights):
            return f(*args, **kwargs)
        else:
            return abort(403)
    return decorated_function

@app.route('/add_admin', methods=['GET', 'POST'])
@admin_only
def add_admin():
    if request.method == 'POST':
        email = request.form.get('email')  # Get the email from the form
        user = User.query.filter_by(email=email).first()  # Assuming you have a User model, retrieve the user by email

        if user:
            user.admin_rights = True  # Set the 'admin_rights' attribute to True
            admin = Admin(email=email)
            db.session.add(admin)
            db.session.commit()  # Commit the changes to the database
            flash('User has been added as an admin.')
            return redirect(url_for('admin_panel'))
        else:
            flash('User not found.')

        return redirect(url_for('add_admin'))  # Redirect to the add admin page

    return render_template('add_admin.html')


@app.route('/admin_panel')
@admin_only
def admin_panel():
    admins = Admin.query.all()
    user = User.query.get(current_user.id)
    return render_template('admin_panel.html', all_admins=admins, user=user)
@app.route('/delete_admin', methods=['POST'])
@admin_only
def delete_admin():
    if request.method == 'POST':
        admin_id = request.form.get('admin_id')  # Get the admin ID from the form
        admin = Admin.query.get(admin_id)  # Assuming you have an Admin model, retrieve the admin by ID

        if admin:
            email = admin.email
            user = User.query.filter_by(email=email).first()  # Retrieve the corresponding user by email
            if user:
                user.admin_rights = False  # Set the 'admin_rights' attribute to False
                db.session.delete(admin)  # Delete the admin from the database
                db.session.commit()  # Commit the changes to the database
                flash('Admin rights have been disabled.')
            else:
                flash('User not found.')
        else:
            flash('Admin not found.')

        return redirect(url_for('admin_panel'))  # Redirect to the admin panel page

    return render_template('delete_admin.html')

# Define the 404 error handler
@app.errorhandler(404)
def page_not_found(error):
    return render_template('template/pages/samples/error-404.html'), 404


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()

    return render_template("index.html", all_posts=posts)

@app.route('/get_conversion_rate', methods=['POST'])
def get_conversion_rate():
    amount = float(request.form['amount'])
    coin = request.form['coin']
    currency = 'USD'  # Set the desired currency

    url = f'https://api.binance.com/api/v3/ticker/price?symbol={coin}'
    response = requests.get(url)
    data = response.json()
    conversion_rate = float(data['price'])
    result = amount * conversion_rate

    return {'result': result}

@app.route("/get_price/<symbol>")
def get_price(symbol):
    url = f'https://api.binance.com/api/v3/ticker/price?symbol={symbol}'
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if 'price' in data:
                price = data['price']
                return jsonify({'symbol': symbol, 'price': price})
            else:
                return render_template("create_new_signal.html", error_message="Symbol not found database")
        return render_template("create_new_signal.html", error_message ="Failed to retrieve price")
    except requests.exceptions.RequestException as e:
        return render_template("create_new_signal.html", error_message=str(e))

@app.route("/get_coin_symbols/<symbol>")
def get_coin_symbols(symbol):
    url = 'https://api.binance.com/api/v3/exchangeInfo'

    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            symbols = []
            for symbol_info in data['symbols']:
                if symbol_info['symbol'].startswith(symbol.upper()):
                    symbols.append(symbol_info['symbol'])
            return jsonify({'symbols': symbols[:10]})  # Return a maximum of 10 suggestions
        return jsonify({'symbols': []})
    except requests.exceptions.RequestException as e:
        return jsonify({'symbols': []})


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # if not form.recaptcha.validate():
        #     flash('Invalid CAPTCHA. Please try again.')
        #     return redirect(url_for("register"))

        if User.query.filter_by(email=form.email.data).first():
            flash("You have already signed up with this email, log in instead")
            return redirect(url_for("login"))
        if User.query.filter_by(username=form.username.data).first():
            flash("This username is already used, try something else")
            return redirect(url_for('register'))
        hash_and_salted = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            firstname = form.firstname.data,
            lastname = form.lastname.data,
            username = form.username.data,
            email = form.email.data,
            password = hash_and_salted
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)

@app.route("/login/google/callback")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        email = resp.json()["email"]
        full_name = data["name"]
        # Check if the email is already registered
        if User.query.filter_by(email=email).first():
            flash("You have already signed up with this email, log in instead")
            return redirect(url_for("login"))

        # Create a new user with the Google email
        new_user = User(
            email=email,
            firstname=full_name.split()[0],  # Assuming the first name is the first word in the full name
            lastname=full_name.split()[-1]
            # You can populate other user fields if available in the response
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    else:
        flash("Failed to fetch user data from Google.")
        return redirect(url_for("register"))

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("This email does not exist, please sign up")
            return redirect(url_for("register"))

        elif not check_password_hash(user.password, password):
            flash("incorrect password, please try again")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form)

def send_reset_email(email, reset_code):
    # Compose the email message
    subject = 'Password Reset Code'
    sender = 'starisborn222@gmail.com'
    recipients = [email]
    body = f"Please use the following code to reset your password: {reset_code}"

    user = User.query.filter_by(email=email).first()
    if user:
        user.reset_code = reset_code
        db.session.commit()
    # Send the email
    message = Message(subject=subject, sender=sender, recipients=recipients, body=body)
    mail.send(message)

def generate_reset_code():
    return str(random.randint(100000, 999999))



@app.route('/forgot_password', methods=["GET", "POST"])
def forgot_password():
    form = ForgotForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            reset_code = generate_reset_code()
            # Save the reset code in the database or a cache for verification

            send_reset_email(user.email, reset_code)
            # Send the reset code to the user's email

            return redirect(url_for('verify_code'))
        else:
            error_message = 'Email not found, please enter a valid email'
            return redirect(url_for('forgot_password', error_message=error_message))

    return render_template('forgot_password.html', form=form)

@app.route('/verify_code', methods=["GET", "POST"])
def verify_code():
    form = VerifyForm()
    if form.validate_on_submit():
        reset_code = form.reset_code.data

        user = User.query.filter_by(reset_code=reset_code).first()

        if user:
            return redirect(url_for('reset_password', reset_code=reset_code))
        else:
            flash("Invalid reset code, Please try again")
            return redirect(url_for('verify_code'))

    return render_template('verify.html', form=form)

@app.route('/reset_password', methods=["GET", "POST"])
def reset_password():
    form = ResetForm()
    reset_code = request.args.get("reset_code")
    if form.validate_on_submit():

        new_password = form.new_password.data
        confirm_password = form.confirm_password.data

        if new_password == confirm_password:
            hashed_password = generate_password_hash(new_password)
            user = User.query.filter_by(reset_code=form.reset_code.data).first()
            user.password = hashed_password
            user.reset_code = None
            db.session.commit()

            flash("You password has been successfully reset, Please login")
            return redirect(url_for('login'))
        else:
            flash('Invalid reset code, Please Try Again')
            return redirect(url_for('reset_password'))
            

    return render_template('reset_password.html', form=form, reset_code=reset_code)






@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for("login"))
        
        new_comment = Comment(
            text = form.comment_text.data,
            comment_author = current_user,
            parent_post = requested_post
        )

        requested_post.clicks += 1


        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/project")
def project():
    return render_template("project.html")

@app.route("/technical")
def technical():
    return render_template("technical.html")

#-----  DASHBOARD QUARTERS ----#
@app.route("/dashboard/<int:user_id>", methods=["GET", "POST"])
@login_required
def dashboard(user_id):

    if current_user.id == user_id:
        user = User.query.get(user_id)
        total_users = User.query.count()
        total_subs = Subscribe.query.count()
        total_clicks = db.session.query(db.func.sum(BlogPost.clicks)).scalar() or 0
        success = request.args.get('success')
        cancel = request.args.get('cancel')

        account_balance = 0
        total_deposited = 0

        payments = Payment.query.filter_by(sender_id=current_user.id).all()
        account_balance = calculate_account_balance(payments)

        total_deposited = sum(payment.deposited_amount for payment in payments)
            
        # Update the account balance and save the changes
        account_balance += total_deposited
        db.session.commit()

        if success == 'True':
            #flash("Payment successful!")
            account_balance = calculate_account_balance(payments)

            total_deposited = sum(payment.deposited_amount for payment in payments)
            
        # Update the account balance and save the changes
            account_balance += total_deposited
            db.session.commit()
        
        return render_template("template/dashboard.html", user=user, total_users=total_users, total_clicks=total_clicks, total_subs=total_subs, account_balance=account_balance, total_deposited=total_deposited)
    else:
        return redirect(url_for('login'))
def calculate_account_balance(payments):
    total_deposit = 0
    total_withdrawal = 0

    for payment in payments:
        if payment.deposited_amount is not None:
            total_deposit += payment.deposited_amount

        # Assuming withdrawals are stored in a separate field, e.g., withdrawal_amount
        if payment.withdrawal_amount is not None:
            total_withdrawal += payment.withdrawal_amount

    account_balance = total_deposit - total_withdrawal

    return account_balance


def check_subscription_status(user):
    # Retrieve the user's subscription record from the database
    subscription = Subscribe.query.filter_by(sub_sender_id=user.id).first()

    if subscription:
        # Check if the subscription is active
        current_time = datetime.now()
        subscription_expiry = subscription.created_at + timedelta(days=subscription.subscription_duration)
        if current_time <= subscription_expiry:
            return True  # User is subscribed and the subscription is active

    return False  # User is either not subscribed or the subscription has expired
@app.route("/subscribe/<int:user_id>", methods=["GET", "POST"])
@login_required
def subscribe(user_id):
    user = User.query.get(user_id)
    
    if request.method == "POST":
        subscription = request.form.get("subscribe")

        if subscription == "1week":
            subscription_plan = "1 Week"
            subscription_cost = 9
            subscription_duration = 7  # Days
        elif subscription == "1month":
            subscription_plan = "1 Month"
            subscription_cost = 36
            subscription_duration = 30  # Days
        elif subscription == "3month":
            subscription_plan = "3 Months"
            subscription_cost = 108
            subscription_duration = 90  # Days
        elif subscription == "1Year":
            subscription_plan = "1 Year"
            subscription_cost = 387
            subscription_duration = 365  # Days
        else:
            subscription_plan = "Free"
            subscription_cost = 0
            subscription_duration = 0

        payments = Payment.query.filter_by(sender_id=user_id).all()
        account_balance = calculate_account_balance(payments)

        if account_balance >= subscription_cost:
            new_balance = account_balance - subscription_cost

            user.payments.deposited_amount = new_balance
            db.session.commit()

            # Perform additional logic for subscription activation, e.g., updating user's subscription status
            subscription_entry = Subscribe(
                created_at = datetime.now(),
                subscription_plan=subscription_plan,
                subscription_cost=subscription_cost,
                subscription_duration=subscription_duration,
                sub_sender_id=current_user.id,
                transactional_date=date.today().strftime("%B %d, %Y")
                )
            db.session.add(subscription_entry)
            db.session.commit()
            flash("Subscription successful!")
            return redirect(url_for("dashboard", user_id=user.id))
        else:
            flash("Insufficient funds in your account to subscribe.")
            return redirect(url_for("dashboard", user_id=user.id))

    return render_template("subscribe.html", user=user)

@app.route('/update_clicks', methods=["POST"])
def update_clicks():
    post_id = request.form.get('post_id')
    post = BlogPost.query.get(post_id)
    if post:
        post.clicks += 1
        db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))

@app.route("/my_profile/<int:user_id>", methods=["GET", "POST"])
@login_required
def my_profile(user_id):
    user = User.query.get(user_id)
    return render_template("template/pages/samples/my_profile.html", user=user)

@app.route("/subscription_history/<int:user_id>", methods=["GET", "POST"])
@login_required
def subscription_history(user_id):
    user = User.query.get(user_id)
    payments = Payment.query.filter_by(sender_id=user_id).all()
    subscribes = Subscribe.query.filter_by(sub_sender_id=user_id).all()

    all_payments = Payment.query.all()
    all_subs = Subscribe.query.all()
    return render_template("template/pages/tables/subscription_history.html", user=user, payments=payments, subscribes=subscribes, all_payments=all_payments, all_subs=all_subs)

@app.route('/settings/<int:user_id>', methods=["GET", "POST"])
@login_required  # Requires the user to be logged in
def settings(user_id):
    user = User.query.get(user_id)
    form = EditForm(
        firstname = user.firstname,
        lastname = user.lastname,
        username = user.username,
        email = user.email
    )  # Create a form for editing user information
    if form.validate_on_submit():
        user.firstname = form.firstname.data  # Update the user's firstname
        user.lastname = form.lastname.data  # Update the user's lastname
        user.username = form.username.data  # Update the user's username
        user.email = form.email.data  # Update the user's email

        db.session.commit()

        flash("Your information has been updated successfully!")
        return redirect(url_for("settings", user_id=user.id))
    return render_template("template/settings.html", form=form, is_edit=True, user=user)


@app.route("/subscription/<int:user_id>")
@login_required
def subscription(user_id):
    user = User.query.get(user_id)
    return render_template("subscription.html", user=user)

@app.route("/payment/callback", methods=["POST"])
@login_required
def payment_callback():
    # Retrieve payment status from the callback request
    payment_status = request.json.get("status")
    deposited_amount = request.json.get("amount")
    payment_id = request.json.get("payment_id")

    # Check the payment status and perform appropriate actions
    if payment_status in ["partially_paid", "finished"]:
        # Payment partially paid or finished, perform necessary actions
        message = "Payment successful"
        save_payment(payment_status, deposited_amount, payment_id)

    elif payment_status == "failed":
        # Payment failed, perform necessary actions
        message = "Payment failed"
        save_payment(payment_status, deposited_amount, payment_id)
    else:
        # Invalid payment status, handle accordingly
        return "Invalid payment status"
    
    url = url_for("dashboard", user_id=current_user.id, message=message, payment_id=payment_id, deposited_amount=deposited_amount, _external=True)
    redirect(url)

def save_payment(payment_status, deposited_amount, payment_id):
    payment = Payment(
        payment_status=payment_status, 
        deposited_amount=deposited_amount, 
        payment_id=payment_id,
        sender_user=current_user,
        transaction_date=date.today().strftime("%B %d, %Y")
        )
    db.session.add(payment)
    db.session.commit()


@app.route("/create_payment/<int:user_id>", methods=["POST"])
def create_payment(user_id):
    # Retrieve payment details from the request
    user = User.query.get(user_id)
    coin = request.form.get("coin")
    amount = request.form.get("amount")
    
    callback_url = url_for('payment_callback', _external=True)  # Replace with your actual callback URL
    success_url = url_for('dashboard', user_id=current_user.id, success=True,  _external=True)  # Replace with your actual success URL
    cancel_url = url_for('dashboard', user_id=current_user.id, cancel=True, _external=True)
    # Make a request to NowPayment API to create a payment
    api_key = "AN3GYQ6-40RM6HW-M6M0WN0-PDRXEBV"  
    url = "https://api.nowpayments.io/v1/invoice"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key
    }
    data = {
        "price_amount": amount,
        "price_currency": "usd",
        "pay_currency": coin,
        "ipn_callback_url": callback_url,
        "success_url": success_url,
        "cancel_url": cancel_url
    }
    response = requests.post(url, json=data, headers=headers)
    payment_data = response.json()

    # Extract the necessary information from the payment response
    payment_link = payment_data['invoice_url']
    deposited_amount = float(payment_data['price_amount'])  # Update deposited_amount based on the payment response
    payment_id = payment_data['id']  # Update payment_id based on the payment response
    payment_status = 'pending'
    

    # Make a request to NowPayment API to get the payment status
    

    save_payment(payment_status, deposited_amount, payment_id)

    # Render the payment template with the payment link
    return render_template("payment.html",user=user, payment_link=payment_link)

#----- END DASHBOARD QUARTERS ----#

@app.route("/free_signals")
def free_signals():
    new_signal = FreeSignal.query.all()
    if not current_user.is_authenticated:
        flash("You need to login to view free signals")
        return redirect(url_for("login"))
    return render_template("free_signals.html", all_free_signal = new_signal, current_user=current_user)

@app.route("/vip_signals")
def vip_signals():
    new_signal = VipSignal.query.all()

    if not current_user.is_authenticated:
        flash("You need to login to view Vip signals")
        return redirect(url_for("login"))

    subscribed = check_subscription_status(current_user)  # Check if the user is subscribed
    
    if not subscribed:  # If the user is not subscribed, block the page
        flash("error: You need to subscribe to access Vip signals")
        return redirect(url_for("dashboard", user_id=current_user.id))
   
    return render_template("vip_signals.html", all_vip_signal=new_signal)


@app.route("/flash_news")
def flash_news():
    return render_template("flash_news.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/pricing_ranking")
def price_ranking():
    

    # Extract the cryptocurrency symbols and prices from the response data
    crypto_data = []
    for crypto in data['data']:
        symbol = crypto['symbol']
        name = crypto['name']
        price = round(crypto['quote']['USD']['price'], 2)
        hour_change = round(crypto['quote']['USD']['percent_change_1h'], 2)
        day_change = round(crypto['quote']['USD']['percent_change_24h'], 2)
        week_change = round(crypto['quote']['USD']['percent_change_7d'], 2)
        market_cap = round(crypto['quote']['USD']['market_cap'], 2)
        volume_24h = round(crypto['quote']['USD']['volume_24h'], 2)
        circulating_supply = round(crypto['circulating_supply'], 2)
        if hour_change < -5:
            price_text = f"<span style='color: red;'>${price}</span>"
        else:
            price_text = f"${price}"
        crypto_data.append({'Symbol': symbol, 'Name': name, 'Price': price_text, '1h %': hour_change, '24h %': day_change, '7d %': week_change,
                            'Market Cap': market_cap, 'Volume(24h)': volume_24h, 'Circulating Supply': circulating_supply})

    return render_template("price_ranking.html", crypto_prices=crypto_data)


@app.route('/refresh')
def refresh():
    return redirect(url_for('price_ranking'))

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        if form.image.data:
            image_file = form.image.data
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
            img_url = f"{request.host_url}static/uploads/{filename}"
        else:
            img_url = None
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            image_filename=filename,
            img_url=img_url,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()

        #send_to_telegram_channel(new_post)
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)

def send_to_telegram_channel(post):
    # Telegram Bot API endpoint
    bot_token = ""
    chat_id = "-1001855823774"
    message = f"New post:\n\nTitle: {post.title}\nSubtitle: {post.subtitle}\n\nRead more: {request.host_url}post/{post.id}"
    send_message_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    # Send a POST request to the Telegram Bot API
    response = requests.get(send_message_url, json={"chat_id": chat_id, "text": message})

    if response.status_code != 200:
        print(f"Failed to send message to Telegram. Status code: {response.status_code}")


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(obj=post)

    if edit_form.validate_on_submit():
        if edit_form.image.data:
            image_file = edit_form.image.data
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
            img_url = f"{request.host_url}static/uploads/{filename}"
            post.image_filename = filename
            post.img_url = img_url

        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.body = edit_form.body.data
        db.session.commit()

        #send_to_telegram_channel(edit_form)
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/create_new_signal", methods=["GET", "POST"])
@admin_only
def create_new_signal():
    form = FreeSignalForm()
    if form.validate_on_submit():
        if form.entry_point.data and form.stop_loss.data and form.take_profit.data and form.coin_symbol.data:
            new_free_signal = FreeSignal(
                entry_point = float(form.entry_point.data),
                stop_loss = float(form.stop_loss.data),
                take_profit = float(form.take_profit.data),
                coin_symbol = form.coin_symbol.data.upper(),
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_free_signal)
            db.session.commit()
            return redirect(url_for("free_signals"))
        else:
            flash("Please fill in all the necessary fields.", "error")
    elif form.errors:
        flash("Form validation Failed", "error")
   
    return render_template("create_new_signal.html", form=form)


@app.route("/edit-signal/<int:signal_id>", methods=["GET", "POST"])
@admin_only
def edit_signal(signal_id):
    signal = FreeSignal.query.get(signal_id)
    edit_form = FreeSignalForm(
        entry_point=float(signal.entry_point),
        stop_loss=float(signal.stop_loss),
        take_profit=float(signal.take_profit),
        coin_symbol=signal.coin_symbol
    )

    if edit_form.validate_on_submit():
        signal.entry_point = float(edit_form.entry_point.data)
        signal.stop_loss = float(edit_form.stop_loss.data)
        signal.take_profit = float(edit_form.take_profit.data)
        signal.coin_symbol = edit_form.coin_symbol.data.upper()
        db.session.commit()
        return redirect(url_for("free_signals", signal_id=signal.id))

    return render_template("create_new_signal.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete_signal/<int:signal_id>")
@admin_only
def delete_signal(signal_id):
    post_to_delete = FreeSignal.query.get(signal_id)
    if post_to_delete is not None:
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('free_signals'))

@app.route("/create_vip_signal", methods=["GET", "POST"])
@admin_only
def create_vip_signal():
    form = VipSignalForm()
    if form.validate_on_submit():
        if form.entry_point.data and form.stop_loss.data and form.take_profit.data and form.coin_symbol.data:
            new_vip_signal = VipSignal(
                entry_point = float(form.entry_point.data),
                stop_loss = float(form.stop_loss.data),
                take_profit = float(form.take_profit.data),
                coin_symbol = form.coin_symbol.data.upper(),
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_vip_signal)
            db.session.commit()
            return redirect(url_for("vip_signals"))
        else:
            flash("Please fill in all the necessary fields.", "error")
    elif form.errors:
        flash("Form validation Failed", "error")
   
    return render_template("create_vip_signal.html", form=form)

@app.route("/edit-vip-signal/<int:signal_id>", methods=["GET", "POST"])
@admin_only
def edit_vip_signal(signal_id):
    signal = VipSignal.query.get(signal_id)

    if signal is None:
        # Handle the case where the signal does not exist
        return "Signal not found."
    edit_form = VipSignalForm(
        entry_point=signal.entry_point,
        stop_loss=signal.stop_loss,
        take_profit=signal.take_profit,
        coin_symbol=signal.coin_symbol
    )
    if edit_form.validate_on_submit():
        signal.entry_point = edit_form.entry_point.data
        signal.stop_loss = edit_form.stop_loss.data
        signal.take_profit = edit_form.take_profit.data
        signal.coin_symbol = edit_form.coin_symbol.data
        db.session.commit()
        return redirect(url_for("vip_signals", signal_id=signal.id))

    return render_template("create_vip_signal.html", form=edit_form, is_edit=True)

@app.route("/delete_vip/<int:signal_id>")
@admin_only
def delete_vip_signal(signal_id):
    post_to_delete = VipSignal.query.get(signal_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('vip_signals'))





if __name__ == "__main__":
    with app.app_context(): 
        app.run(debug=True)
    

while True:
    time.sleep(5)
    refresh()

