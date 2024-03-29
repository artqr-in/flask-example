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

login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username

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
    #return render_template('index.html')
    return redirect("https://artqr.in")

@application.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    username = session.get('username')
    urls = {}
    if os.path.exists('urls.json'):
        with open('urls.json') as url_storage:
            urls = json.load(url_storage)
    session['urls'] = urls
    return render_template('home.html', username=username, urls=urls)

@application.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = form.username.data
        pw = form.password.data
        print(user,pw)
        if (user == "sunny" or user=="bindu") and pw=="admin":
            login_user(User(user))
            session['username'] = user
            return redirect(url_for('home'))

    return render_template('login.html', form=form)
'''
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
'''
@application.route('/shortenurl', methods=['GET', 'POST'])
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
            
@application.route('/delete_entry/<string:key>', methods=['POST'])
def delete_entry(key):
    if request.method == 'POST':
        urls = session.get('urls', {})
        print(urls)
        if key in urls:
            del urls[key]
            session['urls'] = urls
            with open('urls.json', 'w') as url_storage:
                json.dump(urls, url_storage)
            return redirect(url_for('home'))
    return 'Entry not found or invalid request method'
            
@application.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

'''
if __name__ == '__main__':
    application.run(debug=True)
'''