# coding: utf-8

from .base import TestCase
from .base import create_server, sqlalchemy_provider, cache_provider
from .base import db, Client, User, Token


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
        user = User.query.first()
        token = Token(
            user_id=user.id,
            client_id=self.oauth_client.client_id,
            access_token='foo',
            refresh_token='bar',
            expires_in=1000,
        )
        db.session.add(token)
        db.session.commit()

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': token.refresh_token,
            'client_id': self.oauth_client.client_id,
        })
        assert b'refresh_token' in rv.data

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': token.refresh_token,
            'client_id': self.oauth_client.client_id,
            'client_secret': self.oauth_client.client_secret,
        })
        assert b'invalid_grant' in rv.data or b'refresh_token' in rv.data


class TestSQLAlchemyProvider(TestDefaultProvider):
    def create_server(self):
        create_server(self.app, sqlalchemy_provider(self.app))


class TestCacheProvider(TestDefaultProvider):
    def create_server(self):
        create_server(self.app, cache_provider(self.app))
