module vibe.jwt.exceptions;
import std.format;

/**
    An exception signalling that a token has been tampered with
*/
class TokenSigException : Exception {
    this() {
        super("Token has been tampered with.");
    }
}

/**
    An exception signalling that a token is not usable yet
*/
class TokenNotBeforeException : Exception {
    this() {
        super("Token is not usable yet.");
    }
}

/**
    An exception signalling a token has expired.
*/
class TokenExpiredException : Exception {
    this() {
        super("Token has expired.");
    }
}


/**
    An exception signalling a token has expired.
*/
class TokenFieldMissingException : Exception {
    this(string field) {
        super("Field %s was not found in token.".format(field));
    }
}
