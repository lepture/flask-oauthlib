"""
    flask_oauthlib.contrib.apps
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    The bundle of remote app factories for famous third platforms.

    Usage::

        from flask import Flask
        from flask_oauthlib.client import OAuth
        from flask_oauthlib.contrib.apps import github

        app = Flask(__name__)
        oauth = OAuth(app)

        github.register_to(oauth, scope=['user:email'])
        github.register_to(oauth, name='github2')

    Of course, it requires consumer keys in your config::

        GITHUB_CONSUMER_KEY = ''
        GITHUB_CONSUMER_SECRET = ''
        GITHUB2_CONSUMER_KEY = ''
        GITHUB2_CONSUMER_SECRET = ''

    Some apps with OAuth 1.0a such as Twitter could not accept the ``scope``
    argument.

    Contributed by: tonyseek
"""

import copy

from oauthlib.common import unicode_type, bytes_type


__all__ = ['douban', 'dropbox', 'facebook', 'github', 'google', 'linkedin',
           'twitter', 'weibo']


class RemoteAppFactory(object):
    """The factory to create remote app and bind it to given extension.

    :param default_name: the default name which be used for registering.
    :param kwargs: the pre-defined kwargs.
    :param docstring: the docstring of factory.
    """

    def __init__(self, default_name, kwargs, docstring=''):
        assert 'name' not in kwargs
        assert 'register' not in kwargs
        self.default_name = default_name
        self.kwargs = kwargs
        self._kwargs_processor = None
        self.__doc__ = docstring.lstrip()

    def register_to(self, oauth, name=None, **kwargs):
        """Creates a remote app and registers it."""
        kwargs = self._process_kwargs(
            name=(name or self.default_name), **kwargs)
        return oauth.remote_app(**kwargs)

    def create(self, oauth, **kwargs):
        """Creates a remote app only."""
        kwargs = self._process_kwargs(
            name=self.default_name, register=False, **kwargs)
        return oauth.remote_app(**kwargs)

    def kwargs_processor(self, fn):
        """Sets a function to process kwargs before creating any app."""
        self._kwargs_processor = fn
        return fn

    def _process_kwargs(self, **kwargs):
        final_kwargs = copy.deepcopy(self.kwargs)
        # merges with pre-defined kwargs
        final_kwargs.update(copy.deepcopy(kwargs))
        # use name as app key
        final_kwargs.setdefault('app_key', final_kwargs['name'].upper())
        # processes by pre-defined function
        if self._kwargs_processor is not None:
            final_kwargs = self._kwargs_processor(**final_kwargs)
        return final_kwargs


def make_scope_processor(default_scope):
    def processor(**kwargs):
        # request_token_params
        scope = kwargs.pop('scope', [default_scope])  # default scope
        if not isinstance(scope, (unicode_type, bytes_type)):
            scope = ','.join(scope)  # allows list-style scope
        request_token_params = kwargs.setdefault('request_token_params', {})
        request_token_params.setdefault('scope', scope)  # doesn't override
        return kwargs
    return processor


douban = RemoteAppFactory('douban', {
    'base_url': 'https://api.douban.com/v2/',
    'request_token_url': None,
    'access_token_url': 'https://www.douban.com/service/auth2/token',
    'authorize_url': 'https://www.douban.com/service/auth2/auth',
    'access_token_method': 'POST',
}, """
The OAuth app for douban.com API.

:param scope: optional. default: ``['douban_basic_common']``.
              see also: http://developers.douban.com/wiki/?title=oauth2
""")
douban.kwargs_processor(make_scope_processor('douban_basic_common'))


dropbox = RemoteAppFactory('dropbox', {
    'base_url': 'https://www.dropbox.com/1/',
    'request_token_url': None,
    'access_token_url': 'https://api.dropbox.com/1/oauth2/token',
    'authorize_url': 'https://www.dropbox.com/1/oauth2/authorize',
    'access_token_method': 'POST',
    'request_token_params': {},
}, """The OAuth app for Dropbox API.""")


facebook = RemoteAppFactory('facebook', {
    'request_token_params': {'scope': 'email'},
    'base_url': 'https://graph.facebook.com',
    'request_token_url': None,
    'access_token_url': '/oauth/access_token',
    'authorize_url': 'https://www.facebook.com/dialog/oauth',
}, """
The OAuth app for Facebook API.

:param scope: optional. default: ``['email']``.
""")
facebook.kwargs_processor(make_scope_processor('email'))


github = RemoteAppFactory('github', {
    'base_url': 'https://api.github.com/',
    'request_token_url': None,
    'access_token_method': 'POST',
    'access_token_url': 'https://github.com/login/oauth/access_token',
    'authorize_url': 'https://github.com/login/oauth/authorize',
}, """
The OAuth app for GitHub API.

:param scope: optional. default: ``['user:email']``.
""")
github.kwargs_processor(make_scope_processor('user:email'))


google = RemoteAppFactory('google', {
    'base_url': 'https://www.googleapis.com/oauth2/v1/',
    'request_token_url': None,
    'access_token_method': 'POST',
    'access_token_url': 'https://accounts.google.com/o/oauth2/token',
    'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
}, """
The OAuth app for Google API.

:param scope: optional.
              default: ``['https://www.googleapis.com/auth/userinfo.email']``.
""")
google.kwargs_processor(make_scope_processor(
    'https://www.googleapis.com/auth/userinfo.email'))


twitter = RemoteAppFactory('twitter', {
    'base_url': 'https://api.twitter.com/1.1/',
    'request_token_url': 'https://api.twitter.com/oauth/request_token',
    'access_token_url': 'https://api.twitter.com/oauth/access_token',
    'authorize_url': 'https://api.twitter.com/oauth/authenticate',
}, """The OAuth app for Twitter API.""")


weibo = RemoteAppFactory('weibo', {
    'base_url': 'https://api.weibo.com/2/',
    'authorize_url': 'https://api.weibo.com/oauth2/authorize',
    'request_token_url': None,
    'access_token_method': 'POST',
    'access_token_url': 'https://api.weibo.com/oauth2/access_token',
    # since weibo's response is a shit, we need to force parse the content
    'content_type': 'application/json',
}, """
The OAuth app for weibo.com API.

:param scope: optional. default: ``['email']``
""")
weibo.kwargs_processor(make_scope_processor('email'))


def change_weibo_header(uri, headers, body):
    """Since weibo is a rubbish server, it does not follow the standard,
    we need to change the authorization header for it."""
    auth = headers.get('Authorization')
    if auth:
        auth = auth.replace('Bearer', 'OAuth2')
        headers['Authorization'] = auth
    return uri, headers, body

weibo.pre_request = change_weibo_header


linkedin = RemoteAppFactory('linkedin', {
    'request_token_params': {'state': 'RandomString'},
    'base_url': 'https://api.linkedin.com/v1/',
    'request_token_url': None,
    'access_token_method': 'POST',
    'access_token_url': 'https://www.linkedin.com/uas/oauth2/accessToken',
    'authorize_url': 'https://www.linkedin.com/uas/oauth2/authorization',
}, """
The OAuth app for LinkedIn API.

:param scope: optional. default: ``['r_basicprofile']``
""")
linkedin.kwargs_processor(make_scope_processor('r_basicprofile'))


def change_linkedin_query(uri, headers, body):
    auth = headers.pop('Authorization')
    headers['x-li-format'] = 'json'
    if auth:
        auth = auth.replace('Bearer', '').strip()
        if '?' in uri:
            uri += '&oauth2_access_token=' + auth
        else:
            uri += '?oauth2_access_token=' + auth
    return uri, headers, body

linkedin.pre_request = change_linkedin_query
