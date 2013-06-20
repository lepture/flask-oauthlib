# coding: utf-8

import os
import tempfile
import unittest
import json
from urlparse import urlparse
from flask import Flask
from .oauth2_server import create_server, db, enable_log
from .oauth2_client import create_client


class BaseSuite(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.debug = True
        app.testing = True
        app.secret_key = 'development'

        self.db_fd, self.db_file = tempfile.mkstemp()
        config = {
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///%s' % self.db_file
        }
        app.config.update(config)

        app = create_server(app)
        app = create_client(app)

        self.app = app
        self.client = app.test_client()
        return app

    def tearDown(self):
        db.session.remove()
        db.drop_all()

        os.close(self.db_fd)
        os.unlink(self.db_file)


authorize_url = (
    '/oauth/authorize?response_type=code&client_id=dev'
    '&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized&scope=email'
)


class TestWebAuth(BaseSuite):
    def test_login(self):
        rv = self.client.get('/login')
        assert 'response_type=code' in rv.location

    def test_oauth_authorize_invalid_url(self):
        rv = self.client.get('/oauth/authorize')
        assert 'invalid_client_id' in rv.location

    def test_oauth_authorize_valid_url(self):
        rv = self.client.get(authorize_url)
        # valid
        assert '</form>' in rv.data

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
        assert 'access_token' in rv.data

    def test_full_flow(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        assert 'access_token' in rv.data

        rv = self.client.get('/')
        assert 'username' in rv.data

        rv = self.client.get('/address')
        assert rv.status_code == 403

        rv = self.client.get('/method/post')
        assert 'POST' in rv.data

        rv = self.client.get('/method/put')
        assert 'PUT' in rv.data

        rv = self.client.get('/method/delete')
        assert 'DELETE' in rv.data

    def test_invalid_client_id(self):
        authorize_url = (
            '/oauth/authorize?response_type=code&client_id=confidential'
            '&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized'
            '&scope=email'
        )
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        assert 'Invalid' in rv.data

    def test_invalid_response_type(self):
        authorize_url = (
            '/oauth/authorize?response_type=invalid&client_id=dev'
            '&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized'
            '&scope=email'
        )
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        assert 'error' in rv.data


class TestPasswordAuth(BaseSuite):
    def test_get_access_token(self):
        auth_code = 'confidential:confidential'.encode('base64').strip()
        url = ('/oauth/token?grant_type=password&state=foo'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        }, data={'confirm': 'yes'})
        assert 'access_token' in rv.data
        assert 'state' in rv.data


class TestRefreshToken(BaseSuite):
    def test_refresh_token_in_password_grant(self):
        auth_code = 'confidential:confidential'.encode('base64').strip()
        url = ('/oauth/token?grant_type=password'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        })
        assert 'access_token' in rv.data
        data = json.loads(rv.data)

        args = (data.get('scope').replace(' ', '+'),
                data.get('refresh_token'))
        auth_code = 'confidential:confidential'.encode('base64').strip()
        url = ('/oauth/token?grant_type=refresh_token'
               '&scope=%s&refresh_token=%s&username=admin')
        url = url % args
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        })
        assert 'access_token' in rv.data


class TestCredentialAuth(BaseSuite):
    def test_get_access_token(self):
        auth_code = 'confidential:confidential'.encode('base64').strip()
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        }, data={'confirm': 'yes'})
        assert 'access_token' in rv.data

    def test_invalid_auth_header(self):
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic foobar'
        }, data={'confirm': 'yes'})
        assert 'invalid_client' in rv.data

    def test_no_client(self):
        auth_code = 'none:confidential'.encode('base64').strip()
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        }, data={'confirm': 'yes'})
        assert 'invalid_client' in rv.data

    def test_wrong_secret_client(self):
        auth_code = 'confidential:wrong'.encode('base64').strip()
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'HTTP_AUTHORIZATION': 'Basic %s' % auth_code,
        }, data={'confirm': 'yes'})
        assert 'invalid_client' in rv.data


def clean_url(location):
    ret = urlparse(location)
    return '%s?%s' % (ret.path, ret.query)
