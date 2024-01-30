from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import json
import os.path
import sqlite3

application = Flask(__name__)

application.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
#application.config['SQLALCHEMY_DATABASE_URI'] = "sqlite+s3://artqr/code/flask-tutorial/database.db"
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
application.config['SECRET_KEY'] = "thisisasecretkey"
db = SQLAlchemy(application)
bcrypt = Bcrypt(application)

try:
    application.app_context().push()
    db.create_all()
    print("$$$$$$$$$$ connected")
except sqlite3.error as e:
    print("********* Connection Error ")

login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=20)],render_kw={'placeholder':'Username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4,max=20)],render_kw={"placeholder":"Password"})
    submit = SubmitField("Register")
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists please choose a different one!"
            )
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=20)],render_kw={'placeholder':'Username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4,max=20)],render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")

@application.route('/')
def index():
    return render_template('index.html')

@application.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    username = session.get('username')
    urls = {}
    if os.path.exists('urls.json'):
        with open('urls.json') as url_storage:
            urls = json.load(url_storage)
    return render_template('home.html', username=username, urls=urls)

@application.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session['username'] = user.username
                return redirect(url_for('home'))

    return render_template('login.html', form=form)

@application.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@application.route('/shortenurl', methods=['GET', 'POST'])
@login_required
def shortenurl():
    if request.method == 'POST':
        urls = {}
        if os.path.exists('urls.json'):
            with open('urls.json') as url_storage:
                urls = json.load(url_storage)
        if request.form['shortcode'] in urls.keys():
            return redirect(url_for('home'))
        urls[request.form['shortcode']] = request.form['url']
        session['urls'] = urls
        with open('urls.json', 'w') as url_storage:
            json.dump(urls, url_storage)
        return render_template('shortenurl.html', shortcode=request.form['shortcode'])
    elif request.method == 'GET':
        return redirect(url_for('home'))
    else:
        return 'Not a valid request method for this route'


@application.route('/<string:shortcode>')
def shortcode_redirect(shortcode):
    if os.path.exists('urls.json'):
        with open('urls.json') as url_storage:
            urls = json.load(url_storage)
            if shortcode in urls.keys():
                return redirect(urls[shortcode])
            
@application.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

'''
if __name__ == '__main__':
    application.run(debug=True)
'''