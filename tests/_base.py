# coding: utf-8

import base64
import os
import sys
import tempfile
import unittest
from flask_oauthlib.client import prepare_request
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

if sys.version_info[0] == 3:
    python_version = 3
    string_type = str
else:
    python_version = 2
    string_type = unicode

# os.environ['DEBUG'] = 'true'
# for oauthlib 0.6.3
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'


class BaseSuite(unittest.TestCase):
    def setUp(self):
        app = self.create_app()

        self.db_fd, self.db_file = tempfile.mkstemp()
        config = {
            'OAUTH1_PROVIDER_ENFORCE_SSL': False,
            'OAUTH1_PROVIDER_KEY_LENGTH': (3, 30),
            'OAUTH1_PROVIDER_REALMS': ['email', 'address'],
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///%s' % self.db_file
        }
        app.config.update(config)

        self.setup_app(app)

        self.app = app
        self.client = app.test_client()
        return app

    def tearDown(self):
        self.database.session.remove()
        self.database.drop_all()

        os.close(self.db_fd)
        os.unlink(self.db_file)

    @property
    def database(self):
        raise NotImplementedError

    def create_app(self):
        raise NotImplementedError

    def setup_app(self, app):
        raise NotImplementedError

    def patch_request(self, app):
        test_client = app.test_client()

        def make_request(uri, headers=None, data=None, method=None):
            uri, headers, data, method = prepare_request(
                uri, headers, data, method
            )

            # test client is a `werkzeug.test.Client`
            parsed = urlparse(uri)
            uri = '%s?%s' % (parsed.path, parsed.query)
            resp = test_client.open(
                uri, headers=headers, data=data, method=method
            )
            # for compatible
            resp.code = resp.status_code
            return resp, resp.data

        return make_request


def to_unicode(text):
    if not isinstance(text, string_type):
        text = text.decode('utf-8')
    return text


def to_bytes(text):
    if isinstance(text, string_type):
        text = text.encode('utf-8')
    return text


def to_base64(text):
    return to_unicode(base64.b64encode(to_bytes(text)))


def clean_url(location):
    location = to_unicode(location)
    ret = urlparse(location)
    return '%s?%s' % (ret.path, ret.query)
