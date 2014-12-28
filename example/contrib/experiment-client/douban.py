from flask import Flask, url_for, session, jsonify
from flask.ext.oauthlib.contrib.client import OAuth


class AppConfig(object):
    DEBUG = True
    SECRET_KEY = 'your-secret-key'
    DOUBAN_CLIENT_ID = 'your-api-key'
    DOUBAN_CLIENT_SECRET = 'your-api-secret'
    DOUBAN_SCOPE = [
        'douban_basic_common',
        'shuo_basic_r',
    ]

app = Flask(__name__)
app.config.from_object(AppConfig)
app.config.from_pyfile('dev.cfg', silent=True)

oauth = OAuth(app)
# see also https://github.com/requests/requests-oauthlib/pull/138
douban = oauth.remote_app(
    name='douban',
    version='2',
    endpoint_url='https://api.douban.com/',
    access_token_url='https://www.douban.com/service/auth2/token',
    refresh_token_url='https://www.douban.com/service/auth2/token',
    authorization_url='https://www.douban.com/service/auth2/auth',
    compliance_fixes='.douban:douban_compliance_fix')


@app.route('/')
def home():
    if obtain_douban_token():
        response = douban.get('v2/user/~me')
        return jsonify(response=response.json())
    return '<a href="%s">Login</a>' % url_for('oauth_douban')


@app.route('/auth/douban')
def oauth_douban():
    callback_uri = url_for('oauth_douban_callback', _external=True)
    return douban.authorize(callback_uri)


@app.route('/auth/douban/callback')
def oauth_douban_callback():
    response = douban.authorized_response()
    if response:
        store_douban_token(response)
        return repr(dict(response))
    else:
        return '<a href="%s">T_T Denied</a>' % (url_for('oauth_douban'))


@douban.tokengetter
def obtain_douban_token():
    return session.get('token')


@douban.tokensaver
def store_douban_token(token):
    session['token'] = token


if __name__ == '__main__':
    app.run()
