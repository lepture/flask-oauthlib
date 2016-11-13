# coding: utf-8

import json
from .._base import to_base64, to_unicode as u
from .base import TestCase
from .base import create_server, sqlalchemy_provider, cache_provider
from .base import db, Client, User, Token


class TestDefaultProvider(TestCase):
    def create_server(self):
        create_server(self.app)

    def prepare_data(self):
        self.create_server()

        normal_client = Client(
            name='normal_client',
            client_id='normal_client',
            client_secret='normal_secret',
            is_confidential=False,
            _redirect_uris='http://localhost/authorized',
        )

        confidential_client = Client(
            name='confidential_client',
            client_id='confidential_client',
            client_secret='confidential_secret',
            is_confidential=True,
            _redirect_uris='http://localhost/authorized',
        )

        db.session.add(User(username='foo'))
        db.session.add(normal_client)
        db.session.add(confidential_client)
        db.session.commit()

        self.normal_client = normal_client
        self.confidential_client = confidential_client

    def test_normal_get_token(self):
        user = User.query.first()
        token = Token(
            user_id=user.id,
            client_id=self.normal_client.client_id,
            access_token='foo',
            refresh_token='bar',
            expires_in=1000,
        )
        db.session.add(token)
        db.session.commit()

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': token.refresh_token,
            'client_id': self.normal_client.client_id,
        })
        assert b'access_token' in rv.data

    def test_confidential_get_token(self):
        user = User.query.first()
        token = Token(
            user_id=user.id,
            client_id=self.confidential_client.client_id,
            access_token='foo',
            refresh_token='bar',
            expires_in=1000,
        )
        db.session.add(token)
        db.session.commit()

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': token.refresh_token,
            'client_id': self.confidential_client.client_id,
        })
        assert b'error' in rv.data

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': token.refresh_token,
            'client_id': self.confidential_client.client_id,
            'client_secret': self.confidential_client.client_secret,
        })
        assert b'access_token' in rv.data

        token.refresh_token = json.loads(u(rv.data))['refresh_token']
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': token.refresh_token,
        }, headers={
            'authorization': 'Basic ' + to_base64(
                    '%s:%s' % (
                        self.confidential_client.client_id,
                        self.confidential_client.client_secret
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
