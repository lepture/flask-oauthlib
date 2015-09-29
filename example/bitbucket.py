from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth


app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

bitbucket = oauth.remote_app(
    'bitbucket',
    consumer_key='CHANGE_ME',
    consumer_secret='CHANGE_ME',
    request_token_params={},
    base_url='https://bitbucket.org/api/2.0/',
    request_token_url='https://bitbucket.org/api/1.0/oauth/request_token',
    access_token_method='POST',
    access_token_url='https://bitbucket.org/api/1.0/oauth/access_token',
    authorize_url='https://bitbucket.org/api/1.0/oauth/authenticate'
)


@app.route('/')
def index():
    if 'oauth_token' in session:
        me = bitbucket.get('user')
        return jsonify(me.data)
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return bitbucket.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('bitbucket_oauth', None)
    return redirect(url_for('index'))


@app.route('/login/authorized')
def authorized():
    resp = bitbucket.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error'],
            request.args['error_description']
        )
    session['bitbucket_oauth'] = resp
    me = bitbucket.get('user')
    return jsonify(me.data)


@bitbucket.tokengetter
def get_bitbucket_oauth_token():
    if 'bitbucket_oauth' in session:
        resp = session['bitbucket_oauth']
        return resp['oauth_token'], resp['oauth_token_secret']


if __name__ == '__main__':
    app.run()
