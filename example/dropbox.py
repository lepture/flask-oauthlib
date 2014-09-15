from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth


app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

dropbox = oauth.remote_app(
    'dropbox',
    consumer_key='a68mwd4ngywz78d',
    consumer_secret='uzz3hr6spb7cspa',
    request_token_params={},
    base_url='https://www.dropbox.com/1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://api.dropbox.com/1/oauth2/token',
    authorize_url='https://www.dropbox.com/1/oauth2/authorize',
)


@app.route('/')
def index():
    if 'dropbox_token' in session:
        me = dropbox.get('account/info')
        return jsonify(me.data)
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return dropbox.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('dropbox_token', None)
    return redirect(url_for('index'))


@app.route('/login/authorized')
def authorized():
    resp = dropbox.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error'],
            request.args['error_description']
        )
    session['dropbox_token'] = (resp['access_token'], '')
    me = dropbox.get('account/info')
    return jsonify(me.data)


@dropbox.tokengetter
def get_dropbox_oauth_token():
    return session.get('dropbox_token')


if __name__ == '__main__':
    app.run()
