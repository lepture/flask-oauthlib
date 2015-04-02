# coding: utf-8

from .base import TestCase
from .base import create_server, sqlalchemy_provider, cache_provider
from .base import db, Client, User


class TestDefaultProvider(TestCase):
    def create_server(self):
        create_server(self.app)

    def prepare_data(self):
        self.create_server()

        oauth_client = Client(
            name='ios', client_id='pass-client', client_secret='pass-secret',
            _redirect_uris='http://localhost/authorized',
        )

        db.session.add(User(username='foo'))
        db.session.add(oauth_client)
        db.session.commit()

        self.oauth_client = oauth_client

    def test_invalid_username(self):
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'notfound',
            'password': 'right',
            'client_id': self.oauth_client.client_id,
            'client_secret': self.oauth_client.client_secret,
        })
        assert b'error' in rv.data

    def test_invalid_password(self):
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'wrong',
            'client_id': self.oauth_client.client_id,
            'client_secret': self.oauth_client.client_secret,
        })
        assert b'error' in rv.data

    def test_missing_client_secret(self):
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'wrong',
            'client_id': self.oauth_client.client_id,
        })
        assert b'error' in rv.data

    def test_get_token(self):
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'right',
            'client_id': self.oauth_client.client_id,
            'client_secret': self.oauth_client.client_secret,
        })
        assert b'access_token' in rv.data

        # in Authorization
        auth = 'cGFzcy1jbGllbnQ6cGFzcy1zZWNyZXQ='
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'right',
        }, headers={'Authorization': 'Basic %s' % auth})
        assert b'access_token' in rv.data

    def test_disallow_grant_type(self):
        self.oauth_client.disallow_grant_type = 'password'
        db.session.add(self.oauth_client)
        db.session.commit()

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'right',
            'client_id': self.oauth_client.client_id,
            'client_secret': self.oauth_client.client_secret,
        })
        assert b'error' in rv.data


class TestSQLAlchemyProvider(TestDefaultProvider):
    def create_server(self):
        create_server(self.app, sqlalchemy_provider(self.app))


class TestCacheProvider(TestDefaultProvider):
    def create_server(self):
        create_server(self.app, cache_provider(self.app))
