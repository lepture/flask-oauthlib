from flask import Flask, redirect, url_for, session, request
from flask_oauthlib.client import OAuth, weibo_urls


app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
oauth = OAuth()

weibo = oauth.remote_app(
    'weibo',
    consumer_key='909122383',
    consumer_secret='2cdc60e5e9e14398c1cbdf309f2ebd3a',
    request_token_params={'scope': 'email'},
    **weibo_urls
)


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return weibo.authorize(callback=url_for('authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))


@app.route('/login/authorized')
@weibo.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    print resp
    session['oauth_token'] = (resp['access_token'], '')
    timeline = weibo.get('statuses/home_timeline.json')
    return str(timeline)


@weibo.tokengetter
def get_weibo_oauth_token():
    return session.get('oauth_token')


if __name__ == '__main__':
    app.run()
