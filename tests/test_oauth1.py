# coding: utf-8

import os
import tempfile
import unittest
from urlparse import urlparse
from flask import Flask
from .oauth1_server import create_server, db
from .oauth1_client import create_client


class BaseSuite(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.debug = True
        app.testing = True
        app.secret_key = 'development'

        self.db_fd, self.db_file = tempfile.mkstemp()
        config = {
            'OAUTH1_PROVIDER_ENFORCE_SSL': False,
            'OAUTH1_PROVIDER_KEY_LENGTH': (3, 30),
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


class TestWebAuth(BaseSuite):
    def test_access_token(self):
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

    def test_no_confirm(self):
        rv = self.client.get('/login')
        assert 'oauth_token' in rv.location

        auth_url = clean_url(rv.location)
        rv = self.client.post(auth_url, data={
            'confirm': 'no'
        })
        assert 'error=denied' in rv.location


def clean_url(location):
    ret = urlparse(location)
    return '%s?%s' % (ret.path, ret.query)
