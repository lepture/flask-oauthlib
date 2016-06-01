from flask import Flask, redirect, url_for, session, request
from flask_oauthlib.client import OAuth, OAuthException, OAuthRemoteApp, parse_response
from flask_oauthlib.utils import to_bytes
import uuid
import base64
import time

REDDIT_APP_ID = '6WnQXb-elQ3DLw'
REDDIT_APP_SECRET = 'KzQickJEBxNHmt5bpO_HmSiupTw'
# Reddit requires you to set nice User-Agent containing your username
REDDIT_USER_AGENT = 'flask-oauthlib testing by /u/<your_username>'

app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)


class RedditOAuthRemoteApp(OAuthRemoteApp):
    def __init__(self, *args, **kwargs):
        super(RedditOAuthRemoteApp, self).__init__(*args, **kwargs)

    def handle_oauth2_response(self):
        if self.access_token_method != 'POST':
            raise OAuthException(
                'Unsupported access_token_method: %s' %
                self.access_token_method
            )

        client = self.make_client()
        remote_args = {
            'code': request.args.get('code'),
            'client_secret': self.consumer_secret,
            'redirect_uri': session.get('%s_oauthredir' % self.name)
        }
        remote_args.update(self.access_token_params)

        reddit_basic_auth = base64.encodestring('%s:%s' % (REDDIT_APP_ID, REDDIT_APP_SECRET)).replace('\n', '')
        body = client.prepare_request_body(**remote_args)
        while True:
            resp, content = self.http_request(
                self.expand_url(self.access_token_url),
                headers={'Content-Type': 'application/x-www-form-urlencoded',
                         'Authorization': 'Basic %s' % reddit_basic_auth,
                         'User-Agent': REDDIT_USER_AGENT},
                data=to_bytes(body, self.encoding),
                method=self.access_token_method,
            )
            # Reddit API is rate-limited, so if we get 429, we need to retry
            if resp.code != 429:
                break
            time.sleep(1)

        data = parse_response(resp, content, content_type=self.content_type)
        if resp.code not in (200, 201):
            raise OAuthException(
                'Invalid response from %s' % self.name,
                type='invalid_response', data=data
            )
        return data

reddit = RedditOAuthRemoteApp(
    oauth,
    'reddit',
    consumer_key=REDDIT_APP_ID,
    consumer_secret=REDDIT_APP_SECRET,
    request_token_params={'scope': 'identity'},
    base_url='https://oauth.reddit.com/api/v1/',
    request_token_url=None,
    access_token_url='https://www.reddit.com/api/v1/access_token',
    access_token_method='POST',
    authorize_url='https://www.reddit.com/api/v1/authorize'
)

oauth.remote_apps['reddit'] = reddit


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login')
def login():
    callback = url_for('reddit_authorized', _external=True)
    return reddit.authorize(callback=callback, state=uuid.uuid4())


@app.route('/login/authorized')
def reddit_authorized():
    resp = reddit.authorized_response()
    if isinstance(resp, OAuthException):
        print(resp.data)

    if resp is None:
        return 'Access denied: error=%s' % request.args['error'],
    session['reddit_oauth_token'] = (resp['access_token'], '')

    # This request may fail(429 Too Many Requests)
    # If you plan to use API heavily(and not just for auth),
    # it may be better to use PRAW: https://github.com/praw-dev/praw
    me = reddit.get('me')
    return 'Logged in as name=%s link_karma=%s comment_karma=%s' % \
        (me.data['name'], me.data['link_karma'], me.data['comment_karma'])


@reddit.tokengetter
def get_reddit_oauth_token():
    return session.get('reddit_oauth_token')


if __name__ == '__main__':
    app.run()
