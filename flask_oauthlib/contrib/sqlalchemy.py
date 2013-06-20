# coding: utf-8
"""
    flask_oauthlib.contrib.sqlalchemy
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    SQLAlchemy support for OAuth2 provider.

    :copyright: (c) 2013 by Hsiaoming Yang.
"""


def user_handle(session, model, provider):
    """Add user getter for provider."""

    def load_user(username, password, *args, **kwargs):
        return session.query(model).filter_by(
            username=username, password=password
        ).first()

    provider._usergetter = load_user
    return provider


def client_handle(session, model, provider):
    """Add client getter for provider."""

    def load_client(client_id):
        return session.query(model).filter_by(client_id=client_id).first()

    provider._clientgetter = load_client
    return provider


def sqlalchemy_handle(session, provider, user=None, client=None, token=None):
    """Bind getters and setters provided by SQLAlchemy model."""

    if user:
        user_handle(session, user, provider)

    if client:
        client_handle(session, client, provider)

    return provider
