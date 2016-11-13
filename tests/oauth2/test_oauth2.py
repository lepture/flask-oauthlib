# coding: utf-8

import json
from flask import Flask
from mock import MagicMock
from .server import (
    create_server,
    db,
    cache_provider,
    sqlalchemy_provider,
    default_provider,
    Token
)
from .client import create_client
from .._base import BaseSuite, clean_url, to_base64
from .._base import to_unicode as u


class OAuthSuite(BaseSuite):
    @property
    def database(self):
        return db

    def create_oauth_provider(app):
        raise NotImplementedError('Each test class must'
                                  'implement this method.')

    def create_app(self):
        app = Flask(__name__)
        app.debug = True
        app.testing = True
        app.secret_key = 'development'
        return app

    def setup_app(self, app):
        oauth = self.create_oauth_provider(app)
        create_server(app, oauth)
        client = create_client(app)
        client.http_request = MagicMock(
            side_effect=self.patch_request(app)
        )
        self.oauth_client = client
        return app


authorize_url = (
    '/oauth/authorize?response_type=code&client_id=dev'
    '&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized&scope=email'
)


auth_code = to_base64('confidential:confidential')


class TestWebAuth(OAuthSuite):

    def create_oauth_provider(self, app):
        return default_provider(app)

    def test_login(self):
        rv = self.client.get('/login')
        assert 'response_type=code' in rv.location

    def test_oauth_authorize_invalid_url(self):
        rv = self.client.get('/oauth/authorize')
        assert 'Missing+client_id+parameter.' in rv.location

    def test_oauth_authorize_valid_url(self):
        rv = self.client.get(authorize_url)
        assert b'</form>' in rv.data

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

    def test_http_head_oauth_authorize_valid_url(self):
        rv = self.client.head(authorize_url)
        assert rv.headers['X-Client-ID'] == 'dev'

    def test_get_access_token(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        assert b'access_token' in rv.data

    def test_full_flow(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        assert b'access_token' in rv.data

        rv = self.client.get('/')
        assert b'username' in rv.data

        rv = self.client.get('/address')
        assert rv.status_code == 401
        assert b'message' in rv.data

        rv = self.client.get('/method/post')
        assert b'POST' in rv.data

        rv = self.client.get('/method/put')
        assert b'PUT' in rv.data

        rv = self.client.get('/method/delete')
        assert b'DELETE' in rv.data

    def test_no_bear_token(self):
        @self.oauth_client.tokengetter
        def get_oauth_token():
            return 'foo', ''

        rv = self.client.get('/method/put')
        assert b'token not found' in rv.data

    def test_expires_bear_token(self):
        @self.oauth_client.tokengetter
        def get_oauth_token():
            return 'expired', ''

        rv = self.client.get('/method/put')
        assert b'token is expired' in rv.data

    def test_get_client(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        rv = self.client.get("/client")
        assert b'dev' in rv.data

    def test_invalid_response_type(self):
        authorize_url = (
            '/oauth/authorize?response_type=invalid&client_id=dev'
            '&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized'
            '&scope=email'
        )
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        assert b'error' in rv.data

    def test_invalid_scope(self):
        authorize_url = (
            '/oauth/authorize?response_type=code&client_id=dev'
            '&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized'
            '&scope=invalid'
        )
        rv = self.client.get(authorize_url)
        rv = self.client.get(clean_url(rv.location))
        assert b'error' in rv.data
        assert b'invalid_scope' in rv.data


class TestWebAuthCached(TestWebAuth):

    def create_oauth_provider(self, app):
        return cache_provider(app)


class TestWebAuthSQLAlchemy(TestWebAuth):

    def create_oauth_provider(self, app):
        return sqlalchemy_provider(app)


class TestRefreshToken(OAuthSuite):

    def create_oauth_provider(self, app):
        return default_provider(app)

    def test_refresh_token_in_password_grant(self):
        url = ('/oauth/token?grant_type=password'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'access_token' in rv.data
        data = json.loads(u(rv.data))

        args = (data.get('scope').replace(' ', '+'),
                data.get('refresh_token'))
        url = ('/oauth/token?grant_type=refresh_token'
               '&scope=%s&refresh_token=%s')
        url = url % args
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'access_token' in rv.data

    def test_refresh_token_in_authorization_code(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        data = json.loads(u(rv.data))

        args = (data.get('scope').replace(' ', '+'),
                data.get('refresh_token'), 'dev', 'dev')
        url = ('/oauth/token?grant_type=refresh_token'
               '&scope=%s&refresh_token=%s'
               '&client_id=%s&client_secret=%s')
        url = url % args
        rv = self.client.get(url)
        assert b'access_token' in rv.data


class TestRefreshTokenCached(TestRefreshToken):

    def create_oauth_provider(self, app):
        return cache_provider(app)


class TestRefreshTokenSQLAlchemy(TestRefreshToken):

    def create_oauth_provider(self, app):
        return sqlalchemy_provider(app)


class TestRevokeToken(OAuthSuite):

    def create_oauth_provider(self, app):
        return default_provider(app)

    def get_token(self):
        url = ('/oauth/token?grant_type=password'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'_token' in rv.data
        return json.loads(u(rv.data))

    def test_revoke_token(self):
        data = self.get_token()
        tok = Token.query.filter_by(
            refresh_token=data['refresh_token']).first()
        assert tok.refresh_token == data['refresh_token']

        revoke_url = '/oauth/revoke'
        args = {'token': data['refresh_token']}
        self.client.post(revoke_url, data=args, headers={
            'Authorization': 'Basic %s' % auth_code,
        })

        tok = Token.query.filter_by(
            refresh_token=data['refresh_token']).first()
        assert tok is None

    def test_revoke_token_with_hint(self):
        data = self.get_token()
        tok = Token.query.filter_by(
            access_token=data['access_token']).first()
        assert tok.access_token == data['access_token']

        revoke_url = '/oauth/revoke'
        args = {'token': data['access_token'],
                'token_type_hint': 'access_token'}
        self.client.post(revoke_url, data=args, headers={
            'Authorization': 'Basic %s' % auth_code,
        })

        tok = Token.query.filter_by(
            access_token=data['access_token']).first()
        assert tok is None


class TestRevokeTokenCached(TestRefreshToken):

    def create_oauth_provider(self, app):
        return cache_provider(app)


class TestRevokeTokenSQLAlchemy(TestRefreshToken):

    def create_oauth_provider(self, app):
        return sqlalchemy_provider(app)


class TestCredentialAuth(OAuthSuite):

    def create_oauth_provider(self, app):
        return default_provider(app)

    def test_get_access_token(self):
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'access_token' in rv.data

    def test_invalid_auth_header(self):
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic foobar'
        })
        assert b'invalid_client' in rv.data

    def test_no_client(self):
        auth_code = to_base64('none:confidential')
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'invalid_client' in rv.data

    def test_wrong_secret_client(self):
        auth_code = to_base64('confidential:wrong')
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'invalid_client' in rv.data


class TestCredentialAuthCached(TestCredentialAuth):

    def create_oauth_provider(self, app):
        return cache_provider(app)


class TestCredentialAuthSQLAlchemy(TestCredentialAuth):

    def create_oauth_provider(self, app):
        return sqlalchemy_provider(app)


class TestTokenGenerator(OAuthSuite):

    def create_oauth_provider(self, app):

        def generator(request):
            return 'foobar'

        app.config['OAUTH2_PROVIDER_TOKEN_GENERATOR'] = generator
        return default_provider(app)

    def test_get_access_token(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        data = json.loads(u(rv.data))
        assert data['access_token'] == 'foobar'
        assert data['refresh_token'] == 'foobar'


class TestRefreshTokenGenerator(OAuthSuite):

    def create_oauth_provider(self, app):

        def at_generator(request):
            return 'foobar'

        def rt_generator(request):
            return 'abracadabra'

        app.config['OAUTH2_PROVIDER_TOKEN_GENERATOR'] = at_generator
        app.config['OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR'] = rt_generator
        return default_provider(app)

    def test_get_access_token(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(rv.location))
        data = json.loads(u(rv.data))
        assert data['access_token'] == 'foobar'
        assert data['refresh_token'] == 'abracadabra'


class TestConfidentialClient(OAuthSuite):

    def create_oauth_provider(self, app):
        return default_provider(app)

    def test_get_access_token(self):
        url = ('/oauth/token?grant_type=authorization_code&code=12345'
               '&scope=email')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code
        })
        assert b'access_token' in rv.data

    def test_invalid_grant(self):
        url = ('/oauth/token?grant_type=authorization_code&code=54321'
               '&scope=email')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code
        })
        assert b'invalid_grant' in rv.data

    def test_invalid_client(self):
        url = ('/oauth/token?grant_type=authorization_code&code=12345'
               '&scope=email')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % ('foo')
        })
        assert b'invalid_client' in rv.data
