# Based on Stash API:
#  https://confluence.atlassian.com/display/stash/Version+2
# You must configure Incoming Authentication App link for application

from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth
import oauthlib

# Generate keys:
# openssl genrsa -out stash.pem 1024
# openssl rsa -in stash.pem -pubout -out stash.pub

# PyCrypto is required
rsa_key = open('atlassian/stash.pem','r').read().strip()

app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

stash = oauth.remote_app(
    'myapp',
    consumer_key='CHANGE_ME',
    consumer_secret='CHANGE_ME',
    request_token_params={
        'signature_method': oauthlib.oauth1.SIGNATURE_RSA,
        'rsa_key': rsa_key
    },
    base_url='http://SERVER/stash/rest/api/1.0/',
    request_token_url='http://SERVER/stash/plugins/servlet/oauth/request-token',
    # You must specify request_token_method explicitly as POST.
    # If you don't specify request_token_method explicitly then Flask will use GET
    # the result will be empty response from server:
    #  https://answers.atlassian.com/questions/123165/oauth-token-request-fails
    request_token_method='POST',
    access_token_method='POST',
    access_token_url='http://SERVER/stash/plugins/servlet/oauth/access-token',
    authorize_url='http://SERVER/stash/plugins/servlet/oauth/authorize'
)


@app.route('/')
def index():
    if 'oauth_token' in session:
        me = stash.get('user')
        return jsonify(me.data)
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return stash.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('stash_oauth', None)
    return redirect(url_for('index'))


@app.route('/login/authorized')
def authorized():
    resp = stash.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error'],
            request.args['error_description']
        )
    session['stash_oauth'] = resp
    me = stash.get('users')
    return jsonify(me.data)


@stash.tokengetter
def get_stash_oauth_token():
    if 'stash_oauth' in session:
        resp = session['stash_oauth']
        return resp['oauth_token'], resp['oauth_token_secret']


if __name__ == '__main__':
    app.run()

