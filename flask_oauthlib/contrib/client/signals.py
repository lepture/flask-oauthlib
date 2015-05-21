from flask.signals import Namespace

__all__ = ['request_token_fetched']

_signals = Namespace()
request_token_fetched = _signals.signal('request-token-fetched')
