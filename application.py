from flask import Flask
application = Flask(__name__)
@application.route('/')
def hello_sunny():
    return "Hey Sunny! How u doing"
