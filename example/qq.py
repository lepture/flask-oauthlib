# -*- coding: utf-8 -*-
import os
import json
from flask import Flask, redirect, url_for, session, request, jsonify, Markup
from flask_oauthlib.client import OAuth

# get yours at http://connect.qq.com
QQ_APP_ID = os.getenv('QQ_APP_ID', '101187283')
QQ_APP_KEY = os.getenv('QQ_APP_KEY', '993983549da49e384d03adfead8b2489')

app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

qq = oauth.remote_app(
    'qq',
    consumer_key=QQ_APP_ID,
    consumer_secret=QQ_APP_KEY,
    base_url='https://graph.qq.com',
    request_token_url=None,
    request_token_params={'scope': 'get_user_info'},
    access_token_url='/oauth2.0/token',
    authorize_url='/oauth2.0/authorize',
)


def json_to_dict(x):
    '''OAuthResponse class can't parse the JSON data with content-type
-    text/html and because of a rubbish api, we can't just tell flask-oauthlib to treat it as json.'''
    if x.find(b'callback') > -1:
        # the rubbish api (https://graph.qq.com/oauth2.0/authorize) is handled here as special case
        pos_lb = x.find(b'{')
        pos_rb = x.find(b'}')
        x = x[pos_lb:pos_rb + 1]

    try:
        if type(x) != str:  # Py3k
            x = x.decode('utf-8')
        return json.loads(x, encoding='utf-8')
    except:
        return x


def update_qq_api_request_data(data={}):
    '''Update some required parameters for OAuth2.0 API calls'''
    defaults = {
        'openid': session.get('qq_openid'),
        'access_token': session.get('qq_token')[0],
        'oauth_consumer_key': QQ_APP_ID,
    }
    defaults.update(data)
    return defaults


@app.route('/')
def index():
    '''just for verify website owner here.'''
    return Markup('''<meta property="qc:admins" '''
                  '''content="226526754150631611006375" />''')


@app.route('/user_info')
def get_user_info():
    if 'qq_token' in session:
        data = update_qq_api_request_data()
        resp = qq.get('/user/get_user_info', data=data)
        return jsonify(status=resp.status, data=json_to_dict(resp.data))
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return qq.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('qq_token', None)
    return redirect(url_for('get_user_info'))


@app.route('/login/authorized')
def authorized():
    resp = qq.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['qq_token'] = (resp['access_token'], '')

    # Get openid via access_token, openid and access_token are needed for API calls
    resp = qq.get('/oauth2.0/me', {'access_token': session['qq_token'][0]})
    resp = json_to_dict(resp.data)
    if isinstance(resp, dict):
        session['qq_openid'] = resp.get('openid')

    return redirect(url_for('get_user_info'))


@qq.tokengetter
def get_qq_oauth_token():
    return session.get('qq_token')


def convert_keys_to_string(dictionary):
    '''Recursively converts dictionary keys to strings.'''
    if not isinstance(dictionary, dict):
        return dictionary
    return dict((str(k), convert_keys_to_string(v)) for k, v in dictionary.items())


def change_qq_header(uri, headers, body):
    '''On SAE platform, when headers' keys are unicode type, will raise
    ``HTTP Error 400: Bad request``, so need convert keys from unicode to str.
    Otherwise, ignored it.'''
    # uncomment below line while deploy on SAE platform
    # headers = convert_keys_to_string(headers)
    return uri, headers, body

qq.pre_request = change_qq_header


if __name__ == '__main__':
    app.run()
