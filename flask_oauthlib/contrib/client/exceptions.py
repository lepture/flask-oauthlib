__all__ = ['OAuthException', 'AccessTokenNotFound']


class OAuthException(Exception):
    pass


class AccessTokenNotFound(OAuthException):
    pass
