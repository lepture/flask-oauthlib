# coding: utf-8

import json
import base64
from flask import Flask
from .server import create_server, db
from .client import create_client
from .._base import BaseSuite, clean_url
from .._base import to_bytes as b
from .._base import to_unicode as u


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
        create_server(app)
        create_client(app)
        return app


authorize_url = (
    '/oauth/authorize?response_type=code&client_id=dev'
    '&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized&scope=email'
)
auth_code = base64.b64encode(b('confidential:confidential'))


class TestWebAuth(OAuthSuite):
    def test_login(self):
        rv = self.client.get('/login')
        assert 'response_type=code' in rv.location

    def test_oauth_authorize_invalid_url(self):
        rv = self.client.get('/oauth/authorize')
        assert 'invalid_client_id' in rv.location

    def test_oauth_authorize_valid_url(self):
        rv = self.client.get(authorize_url)
        # valid
        assert '</form>' in u(rv.data)

        rv = self.client.post(authorize_url, data=dict(
            confirm='no'
        ))
        assert 'access_denied' in rv.location

        rv = self.client.post(authorize_url, data=dict(
            confirm='yes'
        ))
        # success
        assert 'code=' in rv.location
        assert 'state' not in rv.location

        # test state
        rv = self.client.post(authorize_url + '&state=foo', data=dict(
            confirm='yes'
        ))
        assert 'code=' in rv.location
        assert 'state' in rv.location

    def test_get_access_token(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        assert 'access_token' in u(rv.data)

    def test_full_flow(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        assert 'access_token' in u(rv.data)

        rv = self.client.get('/')
        assert 'username' in u(rv.data)

        rv = self.client.get('/address')
        assert rv.status_code == 403

        rv = self.client.get('/method/post')
        assert 'POST' in u(rv.data)

        rv = self.client.get('/method/put')
        assert 'PUT' in u(rv.data)

        rv = self.client.get('/method/delete')
        assert 'DELETE' in u(rv.data)

    def test_invalid_client_id(self):
        authorize_url = (
            '/oauth/authorize?response_type=code&client_id=confidential'
            '&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized'
            '&scope=email'
        )
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        assert 'Invalid' in u(rv.data)

    def test_invalid_response_type(self):
        authorize_url = (
            '/oauth/authorize?response_type=invalid&client_id=dev'
            '&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized'
            '&scope=email'
        )
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        assert 'error' in u(rv.data)


class TestPasswordAuth(OAuthSuite):
    def test_get_access_token(self):
        url = ('/oauth/token?grant_type=password&state=foo'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        }, data={'confirm': 'yes'})
        assert 'access_token' in u(rv.data)
        assert 'state' in u(rv.data)


class TestRefreshToken(OAuthSuite):
    def test_refresh_token_in_password_grant(self):
        url = ('/oauth/token?grant_type=password'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        })
        assert 'access_token' in u(rv.data)
        data = json.loads(u(rv.data))

        args = (data.get('scope').replace(' ', '+'),
                data.get('refresh_token'))
        url = ('/oauth/token?grant_type=refresh_token'
               '&scope=%s&refresh_token=%s&username=admin')
        url = url % args
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        })
        assert 'access_token' in u(rv.data)


class TestCredentialAuth(OAuthSuite):
    def test_get_access_token(self):
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        }, data={'confirm': 'yes'})
        assert 'access_token' in u(rv.data)

    def test_invalid_auth_header(self):
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic foobar'
        }, data={'confirm': 'yes'})
        assert 'invalid_client' in u(rv.data)

    def test_no_client(self):
        auth_code = base64.b64encode(b('none:confidential'))
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        }, data={'confirm': 'yes'})
        assert 'invalid_client' in u(rv.data)

    def test_wrong_secret_client(self):
        auth_code = base64.b64encode(b('confidential:wrong'))
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        }, data={'confirm': 'yes'})
        assert 'invalid_client' in u(rv.data)
