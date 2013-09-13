# coding: utf-8

import logging
import base64
from flask import request, Response
from oauthlib.common import to_unicode, bytes_type

log = logging.getLogger('flask_oauthlib')


def extract_params():
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


def decode_base64(text):
    """Decode base64 string."""
    # make sure it is bytes
    if not isinstance(text, bytes_type):
        text = text.encode('utf-8')
    return to_unicode(base64.b64decode(text), 'utf-8')


def create_response(headers, body, status):
    """Create response class for Flask."""
    response = Response(body or '')
    for k, v in headers.items():
        response.headers[k] = v

    response.status_code = status
    return response
