# coding: utf-8

import time
from nose.tools import raises
from flask import Flask
from flask_oauthlib.client import OAuth, OAuthException
from .server import create_server, db
from .client import create_client
from .._base import BaseSuite
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class OAuthSuite(BaseSuite):
    @property
    def database(self):
        return db

    def create_app(self):
        app = Flask(__name__)
        app.debug = True
        app.testing = True
        app.secret_key = 'development'
        return app

    def setup_app(self, app):
        self.create_server(app)
        self.create_client(app)

    def create_server(self, app):
        create_server(app)
        return app

    def create_client(self, app):
        create_client(app)
        return app


class TestWebAuth(OAuthSuite):
    def test_full_flow(self):
        rv = self.client.get('/login')
        assert 'oauth_token' in rv.location

        auth_url = clean_url(rv.location)
        rv = self.client.get(auth_url)
        assert '</form>' in rv.data

        rv = self.client.post(auth_url, data={
            'confirm': 'yes'
        })
        assert 'oauth_token' in rv.location

        token_url = clean_url(rv.location)
        rv = self.client.get(token_url)
        assert 'oauth_token_secret' in rv.data

        rv = self.client.get('/')
        assert 'email' in rv.data

        rv = self.client.get('/address')
        assert rv.status_code == 403

        rv = self.client.get('/method/post')
        assert 'POST' in rv.data

        rv = self.client.get('/method/put')
        assert 'PUT' in rv.data

        rv = self.client.get('/method/delete')
        assert 'DELETE' in rv.data

    def test_no_confirm(self):
        rv = self.client.get('/login')
        assert 'oauth_token' in rv.location

        auth_url = clean_url(rv.location)
        rv = self.client.post(auth_url, data={
            'confirm': 'no'
        })
        assert 'error=denied' in rv.location

    def test_invalid_request_token(self):
        rv = self.client.get('/login')
        assert 'oauth_token' in rv.location
        loc = rv.location.replace('oauth_token=', 'oauth_token=a')

        auth_url = clean_url(loc)
        rv = self.client.get(auth_url)
        assert 'error' in rv.location

        rv = self.client.post(auth_url, data={
            'confirm': 'yes'
        })
        assert 'error' in rv.location

auth_header = (
    u'OAuth realm="%(realm)s",'
    u'oauth_nonce="97392753692390970531372987366",'
    u'oauth_timestamp="%(timestamp)d", oauth_version="1.0",'
    u'oauth_signature_method="%(signature_method)s",'
    u'oauth_consumer_key="%(key)s",'
    u'oauth_callback="%(callback)s",'
    u'oauth_signature="%(signature)s"'
)
auth_dict = {
    'realm': 'email',
    'timestamp': int(time.time()),
    'key': 'dev',
    'signature_method': 'HMAC-SHA1',
    'callback': 'http%3A%2F%2Flocalhost%2Fauthorized',
    'signature': 'LngsvwVPnd8vCZ2hr7umJvqb%2Fyw%3D',
}


class TestInvalid(OAuthSuite):
    @raises(OAuthException)
    def test_request(self):
        rv = self.client.get('/login')

    def test_request_token(self):
        rv = self.client.get('/oauth/request_token')
        assert 'error' in rv.data

    def test_access_token(self):
        rv = self.client.get('/oauth/access_token')
        assert 'error' in rv.data

    def test_invalid_realms(self):
        auth_format = auth_dict.copy()
        auth_format['realm'] = 'profile'

        headers = {
            u'Authorization': auth_header % auth_format
        }
        rv = self.client.get('/oauth/request_token', headers=headers)
        assert 'error' in rv.data
        assert 'realm' in rv.data

    def test_no_realms(self):
        auth_format = auth_dict.copy()
        auth_format['realm'] = ''

        headers = {
            u'Authorization': auth_header % auth_format
        }
        rv = self.client.get('/oauth/request_token', headers=headers)
        assert 'secret' in rv.data

    def test_no_callback(self):
        auth_format = auth_dict.copy()
        auth_format['callback'] = ''

        headers = {
            u'Authorization': auth_header % auth_format
        }
        rv = self.client.get('/oauth/request_token', headers=headers)
        assert 'error' in rv.data
        assert 'callback' in rv.data

    def test_invalid_signature_method(self):
        auth_format = auth_dict.copy()
        auth_format['signature_method'] = 'PLAIN'

        headers = {
            u'Authorization': auth_header % auth_format
        }
        rv = self.client.get('/oauth/request_token', headers=headers)
        assert 'error' in rv.data
        assert 'signature' in rv.data

    def create_client(self, app):
        oauth = OAuth(app)

        remote = oauth.remote_app(
            'dev',
            consumer_key='noclient',
            consumer_secret='dev',
            request_token_params={'realm': 'email'},
            base_url='http://localhost/api/',
            request_token_url='http://localhost/oauth/request_token',
            access_token_method='GET',
            access_token_url='http://localhost/oauth/access_token',
            authorize_url='http://localhost/oauth/authorize'
        )
        create_client(app, remote)
        return app


def clean_url(location):
    ret = urlparse(location)
    return '%s?%s' % (ret.path, ret.query)
