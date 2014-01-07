# coding: utf-8
"""
    flask_oauthlib.provider
    ~~~~~~~~~~~~~~~~~~~~~~~

    Implemnts OAuth1 and OAuth2 providers support for Flask.

    :copyright: (c) 2013 - 2014 by Hsiaoming Yang.
"""

# flake8: noqa
from .oauth1 import OAuth1Provider, OAuth1RequestValidator
from .oauth2 import OAuth2Provider, OAuth2RequestValidator
