Additional Features
===================

This documentation covers some additional features, they are not required,
but they may be very helpful.

Request Hooks
-------------

Like Flask, Flask-OAuthlib has before_request and after_request hooks too.
It is usually useful for setting limitation on the client request with
before_request::

    @oauth.before_request
    def limit_client_request():
        client_id = request.values.get('client_id')
        if not client_id:
            return
        client = Client.get(client_id)
        if over_limit(client):
            return abort(403)

        track_request(client)

And you can also modify the response with after_request::

    @oauth.after_request
    def valid_after_request(valid, request):
        if request.user in black_list:
            return False, request
        return valid, oauth
