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
from oauthlib.oauth1 import SIGNATURE_HMAC, SIGNATURE_RSA
from oauthlib.common import to_unicode
from flask import request
SIGNATURE_METHODS = (SIGNATURE_HMAC, SIGNATURE_RSA)

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
        if hasattr(self, '_server'):
            return self._server

        if hasattr(self, '_clientgetter') and \
           hasattr(self, '_tokengetter') and \
           hasattr(self, '_requestgetter'):
            server = OAuth1Server(
                clientgetter=self._clientgetter,
                tokengetter=self._tokengetter,
                requestgetter=self._requestgetter,
            )
            return server
        raise RuntimeError('application not bound to required getters')

    def authorize_handler(self, f):
        """Authorization handler decorator."""
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.method == 'GET':
                return f(*args, **kwargs)
            if request.method == 'POST':
                if not f(*args, **kwargs):
                    # denied by user
                    # TODO: add paramters on uri
                    return redirect(self.error_uri)
                return self.confirm_authorization_request()
        return decorated

    def confirm_authorization_request(self):
        """When consumer confirm the authrozation."""
        server = self.server
        token = request.values.get('oauth_token')
        ret = server.create_authorization_response(token)
        log.debug('Authorization successful.')
        return redirect(ret[0])

    def request_token_handler(self, f):
        """Request token decorator."""

    def access_token_handler(self, f):
        """Access token decorator."""

    def require_oauth(self, *scopes):
        """Protect resource with specified scopes."""


class OAuth1Server(Server):
    def __init__(self, clientgetter, tokengetter, requestgetter,
                 config=None):
        self._clientgetter = clientgetter

        # access token getter
        self._tokengetter = tokengetter

        # request token getter
        self._requestgetter = requestgetter

        if not config:
            config = {}
        self._config = config

    @cached_property
    def allowed_signature_methods(self):
        return self._config.get(
            'OAUTH1_PROVIDER_SIGNATURE_METHODS',
            SIGNATURE_METHODS,
        )

    @property
    def realms(self):
        return self._config.get('OAUTH1_PROVIDER_REALMS', [])

    @property
    def enforce_ssl(self):
        return self._config.get('OAUTH1_PROVIDER_ENFORCE_SSL', True)

    def get_client_secret(self, client_key):
        client = self._clientgetter(client_key=client_key)
        if client:
            return client.client_secret
        return ''

    @property
    def dummy_client(self):
        return to_unicode('dummy_client')

    @property
    def dummy_resource_owner(self):
        return to_unicode('dummy_resource_owner')

    def get_request_token_secret(self, client_key, request_token):
        tok = self._requestgetter(
            client_key=client_key,
            token=request_token
        )
        if tok:
            return tok.secret
        return ''

    def get_access_token_secret(self, client_key, access_token):
        tok = self._tokengetter(
            client_key=client_key,
            token=access_token,
        )
        if tok:
            return tok.secret
        return ''

    def validate_client_key(self, client_key):
        client = self._clientgetter(client_key=client_key)
        if client:
            return True
        return False

    def validate_request_token(self, client_key, request_token):
        tok = self._requestgetter(
            client_key=client_key,
            token=request_token
        )
        if tok:
            return True
        return False

    def validate_access_token(self, client_key, access_token):
        tok = self._tokengetter(
            client_key=client_key,
            token=access_token,
        )
        if tok:
            return True
        return False

    def validate_timestamp_and_nonce(
        self, client_key, timestamp, nonce,
        request_token=None, access_token=None):
        # TODO
        pass

    def validate_redirect_uri(self, client_key, redirect_uri):
        client = self._clientgetter(client_key=client_key)
        if not client:
            return False
        if not client.redirect_uris and redirect_uri is None:
            return True
        return redirect_uri in client.redirect_uris

    def validate_requested_realm(self, client_key, realm):
        # TODO
        pass

    def validate_realm(self, client_key, access_token, uri=None,
                       required_realm=None):
        # TODO
        pass

    def validate_verifier(self, client_key, request_token, verifier):
        # TODO
        pass

    def create_authorization_response(self, request_token):
        # TODO
        pass
