from unittest import TestCase
from flask_oauthlib.provider.oauth2 import OAuth2RequestValidator


class TestOAuth2RequestValidator(TestCase):
    class ClientWithoutSecretValidation(object):
        pass

    class ClientWithSecretProperty(object):
        def __init__(self, client_secret):
            self.__client_secret = client_secret

        @property
        def client_secret(self):
            return self.__client_secret

    class ClientWithSecretValidationMethod(object):
        def __init__(self, client_secret):
            self.__client_secret = client_secret

        def validate_client_secret(self, client_secret):
            return client_secret == self.__client_secret

    def setUp(self):
        self.validator = OAuth2RequestValidator(
            clientgetter=lambda: {},
            tokengetter=lambda: {},
            grantgetter=lambda: {}
        )

    def test_client_without_client_secret(self):
        client = self.ClientWithoutSecretValidation()
        assert self.validator._validate_client_secret(client, None)
        assert self.validator._validate_client_secret(client, '')
        assert self.validator._validate_client_secret(client, 'foo')

    def test_client_with_property(self):
        client = self.ClientWithSecretProperty('foobar')
        assert self.validator._validate_client_secret(client, 'foobar')
        assert not self.validator._validate_client_secret(client, 'foo')

    def test_client_with_validation_method(self):
        client = self.ClientWithSecretValidationMethod('foobar')
        assert self.validator._validate_client_secret(client, 'foobar')
        assert not self.validator._validate_client_secret(client, 'foo')
