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
    """The base class of OAuth application."""

    session_class = None

    def __init__(self, name, **kwargs):
        # oauth property required
        self.name = name
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
        raise NotImplementedError

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

    forward_methods = frozenset([
        'head',
        'get',
        'post',
        'put',
        'delete',
        'patch',
    ])

    # magic: generate methods which forward to self.client
    def _make_method(_method_name):
        def _method(self, url, *args, **kwargs):
            url = urljoin(self.endpoint_url, url)
            return getattr(self.client, _method_name)(url, *args, **kwargs)
        return _method
    for _method_name in forward_methods:
        _method = _make_method(_method_name)
        _method.func_name = _method.__name__ = _method_name
        locals()[_method_name] = _method
    del _make_method
    del _method
    del _method_name


class OAuth1Application(BaseApplication):
    """The remote application for OAuth 1.0a."""

    endpoint_url = OAuthProperty('endpoint_url', default='')
    request_token_url = OAuthProperty('request_token_url')
    access_token_url = OAuthProperty('access_token_url')
    authorization_url = OAuthProperty('authorization_url')

    consumer_key = OAuthProperty('consumer_key')
    consumer_secret = OAuthProperty('consumer_secret')

    session_class = OAuth1Session

    _session_request_token = WebSessionData('req_token')

    @property
    def client(self):
        token = self.obtain_token()
        if token is None:
            raise AccessTokenNotFound
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

    endpoint_url = OAuthProperty('endpoint_url', default='')
    access_token_url = OAuthProperty('access_token_url')
    authorization_url = OAuthProperty('authorization_url')

    client_id = OAuthProperty('client_id')
    client_secret = OAuthProperty('client_secret')
    scope = OAuthProperty('scope', default=None)

    compliance_fixes = OAuthProperty('compliance_fixes', default=None)

    _session_state = WebSessionData('state')
    _session_redirect_url = WebSessionData('redir')

    @property
    def client(self):
        token = self.obtain_token()
        if token is None:
            raise AccessTokenNotFound
        return self.session_class(self.client_id, token=token)

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
