from flask import Flask, render_template, request, redirect, url_for
import json
import os.path
application = Flask(__name__)

'''
def hello_sunny():
    return "Hey Sunny! How u doing"
'''




@application.route('/')
def home():
    return render_template('home.html')


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
