# coding: utf-8
"""
    flask_oauthlib.provider.oauth1
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implemnts OAuth1 provider support for Flask.

    :copyright: (c) 2013 by Hsiaoming Yang.
"""

import logging
from werkzeug import cached_property
from oauthlib.oauth1 import Server

__all__ = ('OAuth1Provider', 'OAuth1Server')

log = logging.getLogger('flask_oauthlib')


class OAuth1Provider(object):
    """Provide secure services using OAuth1.

    Like many other Flask extensions, there are two usage modes. One is
    binding the Flask app instance::

        app = Flask(__name__)
        oauth = OAuth1Provider(app)

    The second possibility is to bind the Flask app later::

        oauth = OAuth1Provider()

        def create_app():
            app = Flask(__name__)
            oauth.init_app(app)
            return app

    And now you can protect the resource with realm::

        @app.route('/api/user')
        @oauth.require_oauth('email', 'username')
        def user():
            return jsonify(g.user)
    """

    def __init__(self, app=None):
        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        This callback can be used to initialize an application for the
        oauth provider instance.
        """
        self.app = app
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['oauthlib.provider.oauth1'] = self

    @cached_property
    def server(self):
        """
        All in one endpoints. This property is created automaticly
        if you have implemented all the getters and setters.
        """

    def authorize_handler(self, f):
        """Authorization handler decorator."""

    def request_token_handler(self, f):
        """Request token decorator."""

    def access_token_handler(self, f):
        """Access token decorator."""

    def require_oauth(self, *scopes):
        """Protect resource with specified scopes."""


class OAuth1Server(Server):
    def __init__(self, clientgetter):
        self._clientgetter = clientgetter
