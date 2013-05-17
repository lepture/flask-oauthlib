from flask import Flask, redirect, url_for, session, request
from flask_oauthlib.client import OAuth, weibo_service


app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
oauth = OAuth()

weibo = oauth.remote_app(
    'weibo',
    consumer_key='909122383',
    consumer_secret='2cdc60e5e9e14398c1cbdf309f2ebd3a',
    request_token_params={'scope': 'email,statuses_to_me_read'},
    **weibo_service
)


@app.route('/')
def index():
    if 'oauth_token' in session:
        access_token = session['oauth_token'][0]
        # weibo is a shit !!!! It cannot be authorized by Bearer Token.
        resp = weibo.get('statuses/home_timeline.json', data={
            'access_token': access_token
        })
        return resp.raw_data
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return weibo.authorize(callback=url_for('authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))


@app.route('/logout')
def logout():
    session.pop('oauth_token', None)
    return redirect(url_for('index'))


@app.route('/login/authorized')
@weibo.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['oauth_token'] = (resp['access_token'], '')
    return redirect(url_for('index'))


@weibo.tokengetter
def get_weibo_oauth_token():
    return session.get('oauth_token')


if __name__ == '__main__':
    app.run()
