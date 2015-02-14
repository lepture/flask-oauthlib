"""
    flask_oauthlib.contrib.client
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    An experiment client with requests-oauthlib as backend.
"""

import os
import contextlib
import warnings
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

from flask import current_app, redirect, request
from requests_oauthlib import OAuth1Session, OAuth2Session
from oauthlib.oauth2.rfc6749.errors import MissingCodeError
from werkzeug.utils import import_string

from .descriptor import OAuthProperty, WebSessionData
from .structure import OAuth1Response, OAuth2Response
from .exceptions import AccessTokenNotFound


__all__ = ['OAuth1Application', 'OAuth2Application']


class BaseApplication(object):
    """The base class of OAuth application.

    An application instance could be used in mupltiple context. It never stores
    any session-scope state in the ``__dict__`` of itself.

    :param name: the name of this application.
    :param clients: optional. a reference to the cached clients dictionary.
    """

    session_class = None
    endpoint_url = OAuthProperty('endpoint_url', default='')

    def __init__(self, name, clients=None, **kwargs):
        # oauth property required
        self.name = name

        if clients:
            self.clients = clients

        # other descriptor assignable attributes
        for k, v in kwargs.items():
            if not hasattr(self.__class__, k):
                raise TypeError('descriptor %r not found' % k)
            setattr(self, k, v)

    def __repr__(self):
        class_name = self.__class__.__name__
        return '<%s:%s at %s>' % (class_name, self.name, hex(id(self)))

    def tokengetter(self, fn):
        self._tokengetter = fn
        return fn

    def obtain_token(self):
        """Obtains the access token by calling ``tokengetter`` which was
        defined by users.

        :returns: token or ``None``.
        """
        tokengetter = getattr(self, '_tokengetter', None)
        if tokengetter is None:
            raise RuntimeError('%r missing tokengetter' % self)
        return tokengetter()

    @property
    def client(self):
        """The lazy-created OAuth session with the return value of
        :meth:`tokengetter`.

        :returns: The OAuth session instance or ``None`` while token missing.
        """
        token = self.obtain_token()
        if token is None:
            raise AccessTokenNotFound
        return self._make_client_with_token(token)

    def _make_client_with_token(self, token):
        """Uses cached client or create new one with specific token."""
        cached_clients = getattr(self, 'clients', None)
        hashed_token = _hash_token(self, token)

        if cached_clients and hashed_token in cached_clients:
            return cached_clients[hashed_token]

        client = self.make_client(token)  # implemented in subclasses
        if cached_clients:
            cached_clients[hashed_token] = client

        return client

    def authorize(self, callback_uri, code=302):
        """Redirects to third-part URL and authorizes.

        :param callback_uri: the callback URI. if you generate it with the
                             :func:`~flask.url_for`, don't forget to use the
                             ``_external=True`` keyword argument.
        :param code: default is 302. the HTTP code for redirection.
        :returns: the redirection response.
        """
        raise NotImplementedError

    def authorized_response(self):
        """Obtains access token from third-part API.

        :returns: the response with the type of :class:`OAuthResponse` dict,
                  or ``None`` if the authorization has been denied.
        """
        raise NotImplementedError

    def request(self, method, url, token=None, *args, **kwargs):
        if token is None:
            client = self.client
        else:
            client = self._make_client_with_token(token)
        url = urljoin(self.endpoint_url, url)
        return getattr(client, method)(url, *args, **kwargs)

    def head(self, *args, **kwargs):
        return self.request('head', *args, **kwargs)

    def get(self, *args, **kwargs):
        return self.request('get', *args, **kwargs)

    def post(self, *args, **kwargs):
        return self.request('post', *args, **kwargs)

    def put(self, *args, **kwargs):
        return self.request('put', *args, **kwargs)

    def delete(self, *args, **kwargs):
        return self.request('delete', *args, **kwargs)

    def patch(self, *args, **kwargs):
        return self.request('patch', *args, **kwargs)


class OAuth1Application(BaseApplication):
    """The remote application for OAuth 1.0a."""

    request_token_url = OAuthProperty('request_token_url')
    access_token_url = OAuthProperty('access_token_url')
    authorization_url = OAuthProperty('authorization_url')

    consumer_key = OAuthProperty('consumer_key')
    consumer_secret = OAuthProperty('consumer_secret')

    session_class = OAuth1Session

    _session_request_token = WebSessionData('req_token')

    def make_client(self, token):
        """Creates a client with specific access token pair.

        :param token: a tuple of access token pair ``(token, token_secret)``
                      or a dictionary of access token response.
        :returns: a :class:`requests_oauthlib.oauth1_session.OAuth1Session`
                  object.
        """
        if isinstance(token, dict):
            access_token = token['token']
            access_token_secret = token['token_secret']
        else:
            access_token, access_token_secret = token
        return self.make_oauth_session(
            resource_owner_key=access_token,
            resource_owner_secret=access_token_secret)

    def authorize(self, callback_uri, code=302):
        oauth = self.make_oauth_session(callback_uri=callback_uri)

        # fetches request token
        response = oauth.fetch_request_token(self.request_token_url)
        request_token = response['oauth_token']
        request_token_secret = response['oauth_token_secret']

        # stores request token and callback uri
        self._session_request_token = (request_token, request_token_secret)

        # redirects to third-part URL
        authorization_url = oauth.authorization_url(self.authorization_url)
        return redirect(authorization_url, code)

    def authorized_response(self):
        oauth = self.make_oauth_session()

        # obtains verifier
        try:
            response = oauth.parse_authorization_response(request.url)
        except ValueError as e:
            if 'denied' not in repr(e).split("'"):
                raise
            return  # authorization denied
        verifier = response['oauth_verifier']

        # restores request token from session
        if not self._session_request_token:
            return
        request_token, request_token_secret = self._session_request_token
        del self._session_request_token

        # obtains access token
        oauth = self.make_oauth_session(
            resource_owner_key=request_token,
            resource_owner_secret=request_token_secret,
            verifier=verifier)
        oauth_tokens = oauth.fetch_access_token(self.access_token_url)
        return OAuth1Response(oauth_tokens)

    def make_oauth_session(self, **kwargs):
        oauth = self.session_class(
            self.consumer_key, client_secret=self.consumer_secret, **kwargs)
        return oauth


class OAuth2Application(BaseApplication):
    """The remote application for OAuth 2."""

    session_class = OAuth2Session

    access_token_url = OAuthProperty('access_token_url')
    authorization_url = OAuthProperty('authorization_url')
    refresh_token_url = OAuthProperty('refresh_token_url', default='')

    client_id = OAuthProperty('client_id')
    client_secret = OAuthProperty('client_secret')
    scope = OAuthProperty('scope', default=None)

    compliance_fixes = OAuthProperty('compliance_fixes', default=None)

    _session_state = WebSessionData('state')
    _session_redirect_url = WebSessionData('redir')

    def make_client(self, token):
        """Creates a client with specific access token dictionary.

        :param token: a dictionary of access token response.
        :returns: a :class:`requests_oauthlib.oauth2_session.OAuth2Session`
                  object.
        """
        return self.make_oauth_session(token=token)

    def tokensaver(self, fn):
        """A decorator to register a callback function for saving refreshed
        token while the old token has expired and the ``refresh_token_url`` has
        been specified.

        It is necessary for using the automatic refresh mechanism.

        :param fn: the callback function with ``token`` as its unique argument.
        """
        self._tokensaver = fn
        return fn

    def authorize(self, callback_uri, code=302, **kwargs):
        oauth = self.make_oauth_session(redirect_uri=callback_uri)
        authorization_url, state = oauth.authorization_url(
            self.authorization_url, **kwargs)
        self._session_state = state
        self._session_redirect_url = callback_uri
        return redirect(authorization_url, code)

    def authorized_response(self):
        oauth = self.make_oauth_session(
            state=self._session_state,
            redirect_uri=self._session_redirect_url)
        del self._session_state
        del self._session_redirect_url

        with self.insecure_transport():
            try:
                token = oauth.fetch_token(
                    self.access_token_url, client_secret=self.client_secret,
                    authorization_response=request.url)
            except MissingCodeError:
                return

        return OAuth2Response(token)

    def make_oauth_session(self, **kwargs):
        # joins scope into unicode
        kwargs.setdefault('scope', self.scope)
        if kwargs['scope']:
            kwargs['scope'] = u','.join(kwargs['scope'])

        # configures automatic token refresh if possible
        if self.refresh_token_url:
            if not hasattr(self, '_tokensaver'):
                raise RuntimeError('missing tokensaver')
            kwargs.setdefault('auto_refresh_url', self.refresh_token_url)
            kwargs.setdefault('auto_refresh_kwargs', {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            })
            kwargs.setdefault('token_updater', self._tokensaver)

        # creates session
        oauth = self.session_class(self.client_id, **kwargs)

        # patches session
        compliance_fixes = self.compliance_fixes
        if compliance_fixes.startswith('.'):
            compliance_fixes = \
                'requests_oauthlib.compliance_fixes' + compliance_fixes
        apply_fixes = import_string(compliance_fixes)
        oauth = apply_fixes(oauth)

        return oauth

    @contextlib.contextmanager
    def insecure_transport(self):
        """Creates a context to enable the oauthlib environment variable in
        order to debug with insecure transport.
        """
        origin = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT')
        if current_app.debug or current_app.testing:
            try:
                os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
                yield
            finally:
                if origin:
                    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = origin
                else:
                    os.environ.pop('OAUTHLIB_INSECURE_TRANSPORT', None)
        else:
            if origin:
                warnings.warn(
                    'OAUTHLIB_INSECURE_TRANSPORT has been found in os.environ '
                    'but the app is not running in debug mode or testing mode.'
                    ' It may put you in danger of the Man-in-the-middle attack'
                    ' while using OAuth 2.', RuntimeWarning)
            yield


def _hash_token(application, token):
    """Creates a hashable object for given token then we could use it as a
    dictionary key.
    """
    if isinstance(token, dict):
        hashed_token = tuple(sorted(token.items()))
    elif isinstance(token, tuple):
        hashed_token = token
    else:
        raise TypeError('%r is unknown type of token' % token)

    return (application.__class__.__name__, application.name, hashed_token)
