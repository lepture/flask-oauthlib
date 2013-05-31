from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth


def create_server(app):
    oauth = OAuth(app)

    dev = oauth.remote_app(
        'dev',
        consumer_key='dev',
        consumer_secret='dev',
        request_token_params={'scope': 'email'},
        base_url='http://127.0.0.1:5000/',
        request_token_url=None,
        access_token_method='GET',
        access_token_url='http://127.0.0.1:5000/access_token',
        authorize_url='http://127.0.0.1:5000/authorize'
    )


    @app.route('/')
    def index():
        if 'dev_token' in session:
            return session['dev_token']
        return redirect(url_for('login'))


    @app.route('/login')
    def login():
        return dev.authorize(callback=url_for('authorized', _external=True))

    @app.route('/logout')
    def logout():
        session.pop('dev_token', None)
        return redirect(url_for('index'))

    @app.route('/authorized')
    @dev.authorized_handler
    def authorized(resp):
        if resp is None:
            return 'Access denied: reason=%s error=%s' % (
                request.args['error_reason'],
                request.args['error_description']
            )
        session['dev_token'] = (resp['access_token'], '')
        return session['dev_token']

    @dev.tokengetter
    def get_oauth_token():
        return session.get('dev_token')

    return app


if __name__ == '__main__':
    # DEBUG=1 python oauth2_client.py
    app = Flask(__name__)
    app.debug = True
    app.secret_key = 'development'
    app = create_server(app)
    app.run(host='localhost', port=8000)
