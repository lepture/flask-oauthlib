import unittest

from flask import Flask
from flask_oauthlib.client import OAuth
from flask_oauthlib.contrib.apps import douban, linkedin
from nose.tools import assert_raises


class RemoteAppFactorySuite(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.oauth = OAuth(self.app)

    def test_douban(self):
        assert 'douban.com' in douban.__doc__
        assert ':param scope:' in douban.__doc__

        c1 = douban.create(self.oauth)
        assert 'api.douban.com/v2' in c1.base_url
        assert c1.request_token_params.get('scope') == 'douban_basic_common'

        assert_raises(KeyError, lambda: c1.consumer_key)
        assert_raises(KeyError, lambda: c1.consumer_secret)

        self.app.config['DOUBAN_CONSUMER_KEY'] = 'douban key'
        self.app.config['DOUBAN_CONSUMER_SECRET'] = 'douban secret'
        assert c1.consumer_key == 'douban key'
        assert c1.consumer_secret == 'douban secret'

        c2 = douban.register_to(self.oauth, 'doudou', scope=['a', 'b'])
        assert c2.request_token_params.get('scope') == 'a,b'

        assert_raises(KeyError, lambda: c2.consumer_key)
        self.app.config['DOUDOU_CONSUMER_KEY'] = 'douban2 key'
        assert c2.consumer_key == 'douban2 key'

    def test_linkedin(self):
        c1 = linkedin.create(self.oauth)
        assert c1.name == 'linkedin'
        assert c1.request_token_params == {
            'state': 'RandomString',
            'scope': 'r_basicprofile',
        }

        c2 = linkedin.register_to(self.oauth, name='l2', scope=['c', 'd'])
        assert c2.name == 'l2'
        assert c2.request_token_params == {
            'state': 'RandomString',
            'scope': 'c,d',
        }, c2.request_token_params
