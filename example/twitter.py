# coding: utf-8

from flask import Flask, session, request, url_for
from flask_oauthlib.client import OAuth, twitter_urls


app = Flask(__name__)
app.debug = True
app.secret_key = 'development'

oauth = OAuth(app)

twitter = oauth.remote_app(
    'twitter',
    consumer_key='xBeXxg9lyElUgwZT6AZ0A',
    consumer_secret='aawnSpNTOVuDCjx7HMh6uSXetjNN8zWLpZwCEU4LBrk',
    **twitter_urls
)

@twitter.tokengetter
def get_twitter_token():
    resp = session['twitter_token']
    if resp:
        return resp['oauth_token'], resp['oauth_token_secret']


@app.route('/')
def index():
    if 'twitter_oauth' in session:
        resp = twitter.get('statuses/home_timeline.json')
        return resp


@app.route('/login')
def login():
    callback_url = url_for('oauthorized', next=request.args.get('next'))
    return twitter.authorize(callback=callback_url or request.referrer or None)


@app.route('/oauthorized')
@twitter.authorized_handler
def oauthorized(resp):
    if resp is None:
        return 'denied'
    session['twitter_oauth'] = resp
    return 'success'


if __name__ == '__main__':
    app.run()
