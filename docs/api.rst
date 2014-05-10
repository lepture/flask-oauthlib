.. _api:

Developer Interface
===================

This part of the documentation covers the interface of Flask-OAuthlib.


Client Reference
----------------

.. module:: flask_oauthlib.client

.. autoclass:: OAuth
   :members:

.. autoclass:: OAuthRemoteApp
   :members:

.. autoclass:: OAuthResponse
   :members:

.. autoclass:: OAuthException
   :members:


OAuth1 Provider
---------------

.. module:: flask_oauthlib.provider

.. autoclass:: OAuth1Provider
   :members:

.. autoclass:: OAuth1RequestValidator
   :members:


OAuth2 Provider
---------------

.. autoclass:: OAuth2Provider
   :members:

.. autoclass:: OAuth2RequestValidator
   :members:


Contrib Reference
-----------------

Here are APIs provided by contributors.

.. module:: flask_oauthlib.contrib.oauth2

.. autofunction:: bind_sqlalchemy

.. autofunction:: bind_cache_grant


.. automodule:: flask_oauthlib.contrib.apps

   .. autofunction:: douban
   .. autofunction:: dropbox
   .. autofunction:: facebook
   .. autofunction:: github
   .. autofunction:: google
   .. autofunction:: linkedin
   .. autofunction:: twitter
   .. autofunction:: weibo
