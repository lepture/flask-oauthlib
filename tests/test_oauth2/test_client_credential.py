# coding: utf-8

from .._base import to_base64
from .base import TestCase
from .base import create_server, sqlalchemy_provider, cache_provider
from .base import db, Client, User


class TestDefaultProvider(TestCase):
    def create_server(self):
        create_server(self.app)

    def prepare_data(self):
        self.create_server()

        oauth_client = Client(
            name='ios', client_id='client', client_secret='secret',
            _redirect_uris='http://localhost/authorized',
        )

        db.session.add(User(username='foo'))
        db.session.add(oauth_client)
        db.session.commit()

        self.oauth_client = oauth_client

    def test_get_token(self):
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'client_credentials',
            'client_id': self.oauth_client.client_id,
            'client_secret': self.oauth_client.client_secret,
        })
        assert b'access_token' in rv.data

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'client_credentials'
        }, headers={
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
