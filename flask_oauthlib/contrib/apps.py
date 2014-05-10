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
        self.__doc__ = docstring

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
        if fn.__doc__:
            # appends docstring
            self.__doc__ = '%s\n%s' % (self.__doc__, fn.__doc__)
        return fn

    def _process_kwargs(self, **kwargs):
        final_kwargs = dict(self.kwargs)
        # merges with pre-defined kwargs
        final_kwargs.update(kwargs)
        # use name as app key
        final_kwargs.setdefault('app_key', final_kwargs['name'].upper())
        # processes by pre-defined function
        if self._kwargs_processor is not None:
            final_kwargs = self._kwargs_processor(**final_kwargs)
        return final_kwargs


douban = RemoteAppFactory('douban', {
    'base_url': 'https://api.douban.com/v2/',
    'access_token_url': 'https://www.douban.com/service/auth2/token',
    'authorize_url': 'https://www.douban.com/service/auth2/auth',
    'access_token_method': 'POST',
}, """The OAuth app for douban.com API.""")


@douban.kwargs_processor
def douban_kwargs_processor(**kwargs):
    """
    :param scope: optional. default: ['douban_basic_common'].
                  see also: http://developers.douban.com/wiki/?title=oauth2
    """
    # request_token_url
    kwargs.setdefault('request_token_url', None)
    # request_token_params
    scope = kwargs.pop('scope', ['douban_basic_common'])  # default scope
    if not isinstance(scope, basestring):
        scope = ','.join(scope)  # allows list-style scope
    request_token_params = kwargs.setdefault('request_token_params', {})
    request_token_params.setdefault('scope', scope)  # doesn't override exists
    return kwargs
