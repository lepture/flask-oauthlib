from flask import Flask
from nose.tools import raises
from flask_oauthlib.client import encode_request_data
from flask_oauthlib.client import OAuthRemoteApp, OAuth
from flask_oauthlib.client import parse_response

try:
    import urllib2 as http
    http_urlopen = 'urllib2.urlopen'
except ImportError:
    from urllib import request as http
    http_urlopen = 'urllib.request.urlopen'

from mock import patch


class Response(object):
    def __init__(self, content, headers=None):
        self.content = content
        self.headers = headers or {}

    @property
    def code(self):
        return self.headers.get('status-code', 500)

    @property
    def status_code(self):
        return self.code

    def read(self):
        return self.content

    def close(self):
        return self


def test_encode_request_data():
    data, _ = encode_request_data('foo', None)
    assert data == 'foo'

    data, f = encode_request_data(None, 'json')
    assert data == '{}'
    assert f == 'application/json'

    data, f = encode_request_data(None, 'urlencoded')
    assert data == ''
    assert f == 'application/x-www-form-urlencoded'


def test_app():
    app = Flask(__name__)
    oauth = OAuth(app)
    remote = oauth.remote_app(
        'dev',
        consumer_key='dev',
        consumer_secret='dev',
        request_token_params={'scope': 'email'},
        base_url='http://127.0.0.1:5000/api/',
        request_token_url=None,
        access_token_method='POST',
        access_token_url='http://127.0.0.1:5000/oauth/token',
        authorize_url='http://127.0.0.1:5000/oauth/authorize'
    )
    client = app.extensions['oauthlib.client']
    assert client.dev.name == 'dev'


def test_parse_xml():
    resp = Response(
        '<foo>bar</foo>', headers={
            'status-code': 200,
            'content-type': 'text/xml'
        }
    )
    parse_response(resp, resp.read())


@raises(AttributeError)
def test_raise_app():
    app = Flask(__name__)
    oauth = OAuth(app)
    client = app.extensions['oauthlib.client']
    assert client.demo.name == 'dev'


class TestOAuthRemoteApp(object):
    @raises(TypeError)
    def test_raise_init(self):
        OAuthRemoteApp('oauth', 'twitter')

    def test_not_raise_init(self):
        OAuthRemoteApp('oauth', 'twitter', app_key='foo')

    def test_lazy_load(self):
        oauth = OAuth()
        twitter = oauth.remote_app(
            'twitter',
            base_url='https://api.twitter.com/1/',
            app_key='twitter'
        )
        assert twitter.base_url == 'https://api.twitter.com/1/'

        app = Flask(__name__)
        app.config.update({
            'twitter': dict(
                request_token_params={'realms': 'email'},
                consumer_key='twitter key',
                consumer_secret='twitter secret',
                request_token_url='request url',
                access_token_url='token url',
                authorize_url='auth url',
            )
        })
        oauth.init_app(app)
        assert twitter.consumer_key == 'twitter key'
        assert twitter.consumer_secret == 'twitter secret'
        assert twitter.request_token_url == 'request url'
        assert twitter.access_token_url == 'token url'
        assert twitter.authorize_url == 'auth url'
        assert twitter.content_type is None
        assert 'realms' in twitter.request_token_params

    def test_lazy_load_with_plain_text_config(self):
        oauth = OAuth()
        twitter = oauth.remote_app('twitter', app_key='TWITTER')

        app = Flask(__name__)
        app.config['TWITTER_CONSUMER_KEY'] = 'twitter key'
        app.config['TWITTER_CONSUMER_SECRET'] = 'twitter secret'
        app.config['TWITTER_REQUEST_TOKEN_URL'] = 'request url'
        app.config['TWITTER_ACCESS_TOKEN_URL'] = 'token url'
        app.config['TWITTER_AUTHORIZE_URL'] = 'auth url'

        oauth.init_app(app)

        assert twitter.consumer_key == 'twitter key'
        assert twitter.consumer_secret == 'twitter secret'
        assert twitter.request_token_url == 'request url'
        assert twitter.access_token_url == 'token url'
        assert twitter.authorize_url == 'auth url'

    @patch(http_urlopen)
    def test_http_request(self, urlopen):
        urlopen.return_value = Response(
            b'{"foo": "bar"}', headers={'status-code': 200}
        )

        resp, content = OAuthRemoteApp.http_request('http://example.com')
        assert resp.code == 200
        assert b'foo' in content

        resp, content = OAuthRemoteApp.http_request(
            'http://example.com/',
            method='GET',
            data={'wd': 'flask-oauthlib'}
        )
        assert resp.code == 200
        assert b'foo' in content

        resp, content = OAuthRemoteApp.http_request(
            'http://example.com/',
            data={'wd': 'flask-oauthlib'}
        )
        assert resp.code == 200
        assert b'foo' in content

    @patch(http_urlopen)
    def test_raise_http_request(self, urlopen):
        error = http.HTTPError(
            'http://example.com/', 404, 'Not Found', None, None
        )
        error.read = lambda: b'o'

        class _Fake(object):
            def close(self):
                return 0

        class _Faker(object):
            _closer = _Fake()

        error.file = _Faker()

        urlopen.side_effect = error
        resp, content = OAuthRemoteApp.http_request('http://example.com')
        assert resp.code == 404
        assert b'o' in content
