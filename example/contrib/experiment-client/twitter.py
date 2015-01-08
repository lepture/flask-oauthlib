from flask import Flask, url_for, session, jsonify
from flask.ext.oauthlib.contrib.client import OAuth


class DefaultConfig(object):
    DEBUG = True
    SECRET_KEY = 'your-secret-key'
    TWITTER_CONSUMER_KEY = 'your-api-key'
    TWITTER_CONSUMER_SECRET = 'your-api-secret'

app = Flask(__name__)
app.config.from_object(DefaultConfig)
app.config.from_pyfile('dev.cfg', silent=True)

oauth = OAuth(app)
twitter = oauth.remote_app(
    name='twitter',
    version='1',
    endpoint_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorization_url='https://api.twitter.com/oauth/authorize')


@app.route('/')
def home():
    if oauth_twitter_token():
        response = twitter.get('statuses/home_timeline.json')
        return jsonify(response=response.json())
    return '<a href="%s">Login</a>' % url_for('oauth_twitter')


@app.route('/auth/twitter')
def oauth_twitter():
    callback_uri = url_for('oauth_twitter_callback', _external=True)
    return twitter.authorize(callback_uri)


@app.route('/auth/twitter/callback')
def oauth_twitter_callback():
    response = twitter.authorized_response()
    if response:
        session['token'] = (response.token, response.token_secret)
        return repr(dict(response))
    else:
        return '<a href="%s">T_T Denied</a>' % (url_for('oauth_twitter'))


@twitter.tokengetter
def oauth_twitter_token():
    return session.get('token')


if __name__ == '__main__':
    app.run()
