from flask import Flask, redirect, url_for, session, request, jsonify, abort
from flask_oauthlib.client import OAuth


def create_oauth(app):
    oauth = OAuth(app)

    remote = oauth.remote_app(
        'dev',
        consumer_key='dev',
        consumer_secret='dev',
        request_token_params={'realm': 'email'},
        base_url='http://127.0.0.1:5000/api/',
        request_token_url='http://127.0.0.1:5000/oauth/request_token',
        access_token_method='GET',
        access_token_url='http://127.0.0.1:5000/oauth/access_token',
        authorize_url='http://127.0.0.1:5000/oauth/authorize'
    )
    return remote


def create_client(app, oauth=None):
    if not oauth:
        oauth = create_oauth(app)

    @app.route('/')
    def index():
        if 'dev_oauth' in session:
            ret = oauth.get('email')
            if isinstance(ret.data, dict):
                return jsonify(ret.data)
            return str(ret.data)
        return redirect(url_for('login'))

    @app.route('/login')
    def login():
        return oauth.authorize(callback=url_for('authorized', _external=True))

    @app.route('/logout')
    def logout():
        session.pop('dev_oauth', None)
        return redirect(url_for('index'))

    @app.route('/authorized')
    def authorized():
        resp = oauth.authorized_response()
        if resp is None:
            return 'Access denied: error=%s' % (
                request.args['error']
            )
        if 'oauth_token' in resp:
            session['dev_oauth'] = resp
            return jsonify(resp)
        return str(resp)

    @app.route('/address')
    def address():
        ret = oauth.get('address/hangzhou')
        if ret.status not in (200, 201):
            return abort(ret.status)
        return ret.raw_data

    @app.route('/method/<name>')
    def method(name):
        func = getattr(oauth, name)
        ret = func('method')
        return ret.raw_data

    @oauth.tokengetter
    def get_oauth_token():
        if 'dev_oauth' in session:
            resp = session['dev_oauth']
            return resp['oauth_token'], resp['oauth_token_secret']

    return oauth


if __name__ == '__main__':
    app = Flask(__name__)
    app.debug = True
    app.secret_key = 'development'
    create_client(app)
    app.run(host='localhost', port=8000)
