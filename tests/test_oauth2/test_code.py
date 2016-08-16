# coding: utf-8

from datetime import datetime, timedelta
from .._base import to_base64
from .base import TestCase
from .base import create_server, sqlalchemy_provider, cache_provider
from .base import db, Client, User, Grant


class TestDefaultProvider(TestCase):
    def create_server(self):
        create_server(self.app)

    def prepare_data(self):
        self.create_server()

        oauth_client = Client(
            name='ios', client_id='code-client', client_secret='code-secret',
            _redirect_uris='http://localhost/authorized',
        )

        db.session.add(User(username='foo'))
        db.session.add(oauth_client)
        db.session.commit()

        self.oauth_client = oauth_client
        self.authorize_url = (
            '/oauth/authorize?response_type=code&client_id=%s'
        ) % oauth_client.client_id

    def test_get_authorize(self):
        rv = self.client.get('/oauth/authorize')
        assert 'client_id' in rv.location

        rv = self.client.get('/oauth/authorize?client_id=no')
        assert 'client_id' in rv.location

        url = '/oauth/authorize?client_id=%s' % self.oauth_client.client_id
        rv = self.client.get(url)
        assert 'error' in rv.location

        rv = self.client.get(self.authorize_url)
        assert b'confirm' in rv.data

    def test_post_authorize(self):
        url = self.authorize_url + '&scope=foo'
        rv = self.client.post(url, data={'confirm': 'yes'})
        assert 'invalid_scope' in rv.location

        url = self.authorize_url + '&scope=email'
        rv = self.client.post(url, data={'confirm': 'yes'})
        assert 'code' in rv.location

        url = self.authorize_url + '&scope='
        rv = self.client.post(url, data={'confirm': 'yes'})
        assert 'error=Scopes+must+be+set' in rv.location

    def test_invalid_token(self):
        rv = self.client.get('/oauth/token')
        assert b'unsupported_grant_type' in rv.data

        rv = self.client.get('/oauth/token?grant_type=authorization_code')
        assert b'error' in rv.data
        assert b'code' in rv.data

        url = (
            '/oauth/token?grant_type=authorization_code'
            '&code=nothing&client_id=%s'
        ) % self.oauth_client.client_id
        rv = self.client.get(url)
        assert b'invalid_client' in rv.data

        url += '&client_secret=' + self.oauth_client.client_secret
        rv = self.client.get(url)
        assert b'invalid_client' not in rv.data
        assert rv.status_code == 401

    def test_invalid_redirect_uri(self):
        authorize_url = (
            '/oauth/authorize?response_type=code&client_id=code-client'
            '&redirect_uri=http://localhost:8000/authorized'
            '&scope=invalid'
        )
        rv = self.client.get(authorize_url)
        assert 'error=' in rv.location
        assert 'Mismatching+redirect+URI' in rv.location

    def test_get_token(self):
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = Grant(
            user_id=1,
            client_id=self.oauth_client.client_id,
            scope='email',
            redirect_uri='http://localhost/authorized',
            code='test-get-token',
            expires=expires,
        )
        db.session.add(grant)
        db.session.commit()

        url = '/oauth/token?grant_type=authorization_code&code=test-get-token'
        rv = self.client.get(
            url + '&client_id=%s' % (self.oauth_client.client_id)
        )
        assert b'invalid_client' in rv.data

        rv = self.client.get(
            url + '&client_id=%s&client_secret=%s' % (
                self.oauth_client.client_id,
                self.oauth_client.client_secret
            )
        )
        assert b'access_token' in rv.data

        grant = Grant(
            user_id=1,
            client_id=self.oauth_client.client_id,
            scope='email',
            redirect_uri='http://localhost/authorized',
            code='test-get-token',
            expires=expires,
        )
        db.session.add(grant)
        db.session.commit()

        rv = self.client.get(url, headers={
            'authorization': 'Basic ' + to_base64(
                    '%s:%s' % (
                        self.oauth_client.client_id,
                        self.oauth_client.client_secret
                    )
                )
        })
        assert b'access_token' in rv.data


class TestSQLAlchemyProvider(TestDefaultProvider):
    def create_server(self):
        create_server(self.app, sqlalchemy_provider(self.app))


class TestCacheProvider(TestDefaultProvider):
    def create_server(self):
        create_server(self.app, cache_provider(self.app))

    def test_get_token(self):
        url = self.authorize_url + '&scope=email'
        rv = self.client.post(url, data={'confirm': 'yes'})
        assert 'code' in rv.location
        code = rv.location.split('code=')[1]

        url = (
            '/oauth/token?grant_type=authorization_code'
            '&code=%s&client_id=%s'
        ) % (code, self.oauth_client.client_id)
        rv = self.client.get(url)
        assert b'invalid_client' in rv.data

        url += '&client_secret=' + self.oauth_client.client_secret
        rv = self.client.get(url)
        assert b'access_token' in rv.data
