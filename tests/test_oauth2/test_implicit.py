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
            name='ios', client_id='imp-client', client_secret='imp-secret',
            _redirect_uris='http://localhost/authorized',
        )

        db.session.add(User(username='foo'))
        db.session.add(oauth_client)
        db.session.commit()

        self.oauth_client = oauth_client

    def test_implicit(self):
        rv = self.client.post('/oauth/authorize', data={
            'response_type': 'token',
            'confirm': 'yes',
            'scope': 'email',
            'client_id': self.oauth_client.client_id,
            'client_secret': self.oauth_client.client_secret,
        })
        assert 'access_token' in rv.location


class TestSQLAlchemyProvider(TestDefaultProvider):
    def create_server(self):
        create_server(self.app, sqlalchemy_provider(self.app))


class TestCacheProvider(TestDefaultProvider):
    def create_server(self):
        create_server(self.app, cache_provider(self.app))
