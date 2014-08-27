import unittest
import wsgiref.util
from contextlib import contextmanager
import mock
import werkzeug.wrappers
from flask_oauthlib.utils import extract_params
from oauthlib.common import Request


@contextmanager
def set_flask_request(wsgi_environ):
    """
    Test helper context manager that mocks the flask request global I didn't
    need the whole request context just to test the functions in helpers and I
    wanted to be able to set the raw WSGI environment
    """
    environ = {}
    environ.update(wsgi_environ)
    wsgiref.util.setup_testing_defaults(environ)
    r = werkzeug.wrappers.Request(environ)

    with mock.patch.dict(extract_params.__globals__, {'request': r}):
        yield


class UtilsTestSuite(unittest.TestCase):

    def test_extract_params(self):
        with set_flask_request({'QUERY_STRING': 'test=foo&foo=bar'}):
            uri, http_method, body, headers = extract_params()
            self.assertEquals(uri, 'http://127.0.0.1/?test=foo&foo=bar')
            self.assertEquals(http_method, 'GET')
            self.assertEquals(body, {})
            self.assertEquals(headers, {'Host': '127.0.0.1'})

    def test_extract_params_with_urlencoded_json(self):
        wsgi_environ = {
            'QUERY_STRING': 'state=%7B%22t%22%3A%22a%22%2C%22i%22%3A%22l%22%7D'
        }
        with set_flask_request(wsgi_environ):
            uri, http_method, body, headers = extract_params()
            # Request constructor will try to urldecode the querystring, make
            # sure this doesn't fail.
            Request(uri, http_method, body, headers)
