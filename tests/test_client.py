from flask import Flask
from nose.tools import raises
from flask_oauthlib.client import encode_request_data, add_query
from flask_oauthlib.client import OAuthRemoteApp, OAuth
from flask_oauthlib.client import make_request, parse_response

try:
    import urllib2 as http
    http_urlopen = 'urllib2.urlopen'
except ImportError:
    from urllib import request as http
    http_urlopen = 'urllib.request.urlopen'

from mock import patch
from .oauth2.client import create_client


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


def test_add_query():
    assert 'path' == add_query('path', None)
    assert 'path?foo=foo' == add_query('path', {'foo': 'foo'})
    assert '?path&foo=foo' == add_query('?path', {'foo': 'foo'})


def test_app():
    app = Flask(__name__)
    app = create_client(app)
    client = app.extensions['oauthlib.client']
    assert client.dev.name == 'dev'


@patch(http_urlopen)
def test_make_request(urlopen):
    urlopen.return_value = Response(
        b'{"foo": "bar"}', headers={'status-code': 200}
    )

    resp, content = make_request('http://example.com')
    assert resp.code == 200
    assert b'foo' in content

    resp, content = make_request('http://example.com/',
                                 method='GET',
                                 data={'wd': 'flask-oauthlib'})
    assert resp.code == 200
    assert b'foo' in content

    resp, content = make_request('http://example.com/',
                                 data={'wd': 'flask-oauthlib'})
    assert resp.code == 200
    assert b'foo' in content


@patch(http_urlopen)
def test_raise_make_request(urlopen):
    error = http.HTTPError(
        'http://example.com/', 404, 'Not Found', None, None
    )
    error.read = lambda: b'o'
    urlopen.side_effect = error
    resp, content = make_request('http://example.com')
    assert resp.code == 404
    assert b'o' in content


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
    app = create_client(app)
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
