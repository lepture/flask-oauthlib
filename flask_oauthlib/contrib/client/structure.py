import operator


__all__ = ['OAuth1Response', 'OAuth2Response']


class OAuth1Response(dict):
    token = property(operator.itemgetter('oauth_token'))
    token_secret = property(operator.itemgetter('oauth_token_secret'))


class OAuth2Response(dict):
    access_token = property(operator.itemgetter('access_token'))
    refresh_token = property(operator.itemgetter('refresh_token'))
    token_type = property(operator.itemgetter('token_type'))
    expires_in = property(operator.itemgetter('expires_in'))
    expires_at = property(operator.itemgetter('expires_at'))
