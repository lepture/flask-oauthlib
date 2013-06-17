from flask import Flask
from nose.tools import raises
from flask_oauthlib.client import encode_request_data, add_query
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
