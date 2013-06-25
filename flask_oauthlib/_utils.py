# coding: utf-8

import logging
from flask import request

log = logging.getLogger('flask_oauthlib')


def _extract_params():
    """Extract request params."""
    uri = request.url
    http_method = request.method
    headers = dict(request.headers)
    if 'wsgi.input' in headers:
        del headers['wsgi.input']
    if 'wsgi.errors' in headers:
        del headers['wsgi.errors']
    if 'Http-Authorization' in headers:
        headers['Authorization'] = headers['Http-Authorization']

    body = request.form.to_dict()
    return uri, http_method, body, headers
