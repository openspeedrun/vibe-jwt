module vibe.jwt.auth;
import vibe.jwt.token : Token;

import vibe.http.server;
import vibe.core.log : logInfo;

public import vibe.jwt.token : getRandomJWTKey;

/**
    Implements JWT check
*/
template implemementJWT(InfoType, alias keyFunc = getRandomJWTKey) {
    import vibe.web.web : noRoute;
    import vibe.http.server : HTTPServerRequest, HTTPServerResponse;
    import vibe.core.log : logInfo;
    import backend.user : User;

    @noRoute
    @trusted
    static InfoType authenticate(scope HTTPServerRequest req, scope HTTPServerResponse res) {
        import std.algorithm.searching : startsWith;
        immutable(string) header = req.headers.get("Authorization", null);

        // Header does not exist
        if (header is null) throw new HTTPStatusException(HTTPStatus.unauthorized);

        if (!header.startsWith("Bearer ")) throw new HTTPStatusException(HTTPStatus.unauthorized);

        // Verify token
        auto token = new Token(header[7..$]);
        
        try {
            token.verify(keyFunc());
        } catch (Exception ex) {
            throw new HTTPStatusException(HTTPStatus.forbidden, ex.msg);
        }

        // Token is fine, continue on.
        static if (is(InfoType == class)) {
            return new InfoType(token);
        } else {
            return InfoType(token);
        }
    }
}

/**
    Base interface that implements JWT checks
*/
interface JWTEndpoint(T) {
    mixin implemementJWT!T;
}