from flask import Flask
from nose.tools import raises
from flask_oauthlib.client import encode_request_data, add_query, OAuth
from .oauth2_client import create_client


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


@raises(AttributeError)
def test_raise_app():
    app = Flask(__name__)
    app = create_client(app)
    client = app.extensions['oauthlib.client']
    assert client.demo.name == 'dev'


@raises(ValueError)
def test_bad_base_url():
    app = Flask(__name__)
    oauth = OAuth(app)

    oauth.remote_app(
        'dev',
        consumer_key='dev',
        consumer_secret='dev',
        request_token_params={'scope': 'email'},
        base_url='127.0.0.1:5000/api/',
        request_token_url=None,
        access_token_method='GET',
        access_token_url='http://127.0.0.1:5000/oauth/token',
        authorize_url='http://127.0.0.1:5000/oauth/authorize'
    )
