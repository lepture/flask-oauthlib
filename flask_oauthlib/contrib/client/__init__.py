import copy

from .application import OAuth1Application, OAuth2Application


__all__ = ['OAuth', 'OAuth1Application', 'OAuth2Application']


class OAuth(object):
    """The extension to integrate OAuth 1.0a/2.0 to Flask applications.

        oauth = OAuth(app)

    or::

        oauth = OAuth()
        oauth.init_app(app)
    """

    state_key = 'oauthlib.contrib.client'

    def __init__(self, app=None):
        self.remote_apps = {}
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.extensions = getattr(app, 'extensions', {})
        app.extensions[self.state_key] = self

    def add_remote_app(self, remote_app, name=None, **kwargs):
        """Adds remote application and applies custom attributes on it.

        If the application instance's name is different from the argument
        provided name, or the keyword arguments is not empty, then the
        application instance will not be modified but be copied as a
        prototype.

        :param remote_app: the remote application instance.
        :type remote_app: the subclasses of :class:`BaseApplication`
        :params kwargs: the overriding attributes for the application instance.
        """
        if name is None:
            name = remote_app.name
        if name != remote_app.name or kwargs:
            remote_app = copy.copy(remote_app)
            remote_app.name = name
            vars(remote_app).update(kwargs)
        self.remote_apps[name] = remote_app
        return remote_app

    def remote_app(self, name, version, **kwargs):
        """Creates and adds new remote application.

        :param name: the remote application's name.
        :param version: '1' or '2', the version code of OAuth protocol.
        :param kwargs: the attributes of remote application.
        """
        if version == '1':
            remote_app = OAuth1Application(name)
        elif version == '2':
            remote_app = OAuth2Application(name)
        else:
            raise ValueError('unkonwn version %r' % version)
        return self.add_remote_app(remote_app, **kwargs)

    def __getitem__(self, name):
        return self.remote_apps[name]
