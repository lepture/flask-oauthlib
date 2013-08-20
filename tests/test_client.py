from flask import Flask
from nose.tools import raises
from flask_oauthlib.client import encode_request_data, add_query
from flask_oauthlib.client import OAuthRemoteApp, OAuth, make_request
from .oauth2.client import create_client


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


def test_make_request():
    resp, content = make_request('http://www.baidu.com/')
    assert resp.code == 200
    assert b'form' in content

    resp, content = make_request('http://www.baidu.com/s',
                                 method='GET',
                                 data={'wd': 'flask-oauthlib'})
    assert resp.code == 200
    assert b'flask-oauthlib' in content


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
