from flask import current_app, session


__all__ = ['OAuthProperty', 'WebSessionData']


class OAuthProperty(object):
    """The property which providing config item to remote applications.

    The application classes must have ``name`` to identity themselves.
    """

    _missing = object()

    def __init__(self, name, default=_missing):
        self.name = name
        self.default = default

    def __get__(self, instance, owner):
        if instance is None:
            return self

        # instance resources
        instance_namespace = vars(instance)
        instance_ident = instance.name

        # gets from instance namespace
        if self.name in instance_namespace:
            return instance_namespace[self.name]

        # gets from app config (or default value)
        config_name = '{0}_{1}'.format(instance_ident, self.name).upper()
        if config_name not in current_app.config:
            if self.default is not self._missing:
                return self.default
            exception_message = (
                '{0!r} missing {1} \n\n You need to provide it in arguments'
                ' `{0.__class__.__name__}(..., {1}="foobar", ...)` or in '
                'app.config `{2}`').format(instance, self.name, config_name)
            raise RuntimeError(exception_message)
        return current_app.config[config_name]

    def __set__(self, instance, value):
        # assigns into instance namespace
        instance_namespace = vars(instance)
        instance_namespace[self.name] = value


class WebSessionData(object):
    """The property which providing accessing of Flask session."""

    key_format = '_oauth_{0}_{1}'

    def __init__(self, ident):
        self.ident = ident

    def make_key(self, instance):
        return self.key_format.format(instance.name, self.ident)

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return session.get(self.make_key(instance))

    def __set__(self, instance, value):
        session[self.make_key(instance)] = value

    def __delete__(self, instance):
        session.pop(self.make_key(instance), None)
