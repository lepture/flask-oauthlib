# coding: utf-8

import base64
from flask import request, Response
from oauthlib.common import to_unicode, bytes_type


def extract_params():
    """Extract request params."""
    uri = request.url
    http_method = request.method
    headers = dict(request.headers)
    if 'wsgi.input' in headers:
        del headers['wsgi.input']
    if 'wsgi.errors' in headers:
        del headers['wsgi.errors']

    body = request.form.to_dict()
    return uri, http_method, body, headers


def to_bytes(text, encoding='utf-8'):
    """Make sure text is bytes type."""
    if not text:
        return text
    if not isinstance(text, bytes_type):
        text = text.encode(encoding)
    return text


def decode_base64(text, encoding='utf-8'):
    """Decode base64 string."""
    text = to_bytes(text, encoding)
    return to_unicode(base64.b64decode(text), encoding)


def create_response(headers, body, status):
    """Create response class for Flask."""
    response = Response(body or '')
    for k, v in headers.items():
        response.headers[k] = v

    response.status_code = status
    return response
