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
    if 'twitter_token' in session and 'twitter_secret' in session:
        return session['twitter_token'], session['twitter_secret']


@app.route('/login')
def login():
    callback_url = url_for('oauthorized', next=request.args.get('next'))
    return twitter.authorize(callback=callback_url or request.referrer or None)


@app.route('/oauthorized')
def oauthorized():
    pass


if __name__ == '__main__':
    app.run()
