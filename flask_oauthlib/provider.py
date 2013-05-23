# coding: utf-8
"""
Flask-OAuthlib
--------------

Implemnts OAuth2 provider support for Flask.

:copyright: (c) 2013 by Hsiaoming Yang.
"""

from oauthlib.oauth2 import Server


class OAuth(Server):
    """Provide secure services using OAuth2.

    ::

        @app.route('/statuses/timeline')
        @oauth.protect(scope='statuses')
        def timeline():
            ...
    """

    def __init__(self, scopes=None):
        self.scopes = scopes

    def protect(self, scope=None, methods=None):
        pass

    def access_token_handler(self, f):
        pass

    def refresh_token_handler(self, f):
        pass
