from flask_oauthlib.client import encode_request_data, add_query


def test_encode_request_data():
    data, _ = encode_request_data('foo', None)
    assert data == 'foo'

    data, f = encode_request_data(None, 'json')
    assert data == '{}'
    assert f == 'application/json'

    data, f = encode_request_data(None, 'urlencoded')
    assert data == ''
    assert f == 'application/x-www-form-urlencoded'


def test_add_query():
    assert 'path' == add_query('path', None)
    assert 'path?foo=foo' == add_query('path', {'foo': 'foo'})
    assert '?path&foo=foo' == add_query('?path', {'foo': 'foo'})
