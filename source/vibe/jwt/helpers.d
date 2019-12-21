module vibe.jwt.helpers;
import vibe.jwt.token;
import vibe.data.json;
import std.format;
import secured.mac;
import secured.hash : HashAlgorithm;
import secured.random;
import std.base64 : Base64URLNoPadding;

/**
    Validates the structure of the JWT token
*/
bool validateJWTStructure(string jwtString) {
    import std.algorithm.searching : count;
    return jwtString.count(".") == 2;
}

/**
    Generate a signature for a JWT token
*/
string genSignature(Header header, Json payload, ubyte[] secret) {
    string toSign = "%s.%s".format(header.toString().b64Encode(), payload.toString().b64Encode());

    // All the signing here does somewhat the same, just passes a different SHA algorithm in
    final switch(header.algorithm) {
        case Algorithm.HS256:
            return hmac_ex(secret, stringToBytes(toSign), HashAlgorithm.SHA2_256).b64Encode();
        case Algorithm.HS384:
            return hmac_ex(secret, stringToBytes(toSign), HashAlgorithm.SHA2_384).b64Encode();
        case Algorithm.HS512:
            return hmac_ex(secret, stringToBytes(toSign), HashAlgorithm.SHA2_512).b64Encode();
    }
}

/**
    Verify that the jwt hasn't been tampered with
*/
bool verifySignature(string token, ubyte[] secret) {
    return verifySignature(new Token(token), secret);
}

/**
    Verify that the jwt hasn't been tampered with
*/
bool verifySignature(Token token, ubyte[] secret) {
    string toSign = "%s.%s".format(token.header.toString().b64Encode(), token.payload.toString().b64Encode());

    // All the verifications here does somewhat the same, just passes a different SHA algorithm in
    final switch(token.header.algorithm) {
        case Algorithm.HS256:
            return hmac_verify_ex(token.signature.b64Decode, secret, stringToBytes(toSign), HashAlgorithm.SHA2_256);
        case Algorithm.HS384:
            return hmac_verify_ex(token.signature.b64Decode, secret, stringToBytes(toSign), HashAlgorithm.SHA2_384);
        case Algorithm.HS512:
            return hmac_verify_ex(token.signature.b64Decode, secret, stringToBytes(toSign), HashAlgorithm.SHA2_512);
    }
}

/// Generate a cryptographically secure random key
ubyte[] generateKey(int length = 16) {
    return random(length);
}

/// Encode a string to a base64 string that is compatible
string b64Encode(string data) {
    return Base64URLNoPadding.encode(stringToBytes(data));
}

/// Encode a byte array to a base64 string that is compatible
string b64Encode(ubyte[] data) {
    return Base64URLNoPadding.encode(data);
}

/// Decode a base64 string to a series of bytes
ubyte[] b64Decode(string b64) {
    return Base64URLNoPadding.decode(b64);
}

/// Convert a string to an array of bytes
ubyte[] stringToBytes(string utf8) {
    import std.string : representation;
    return utf8.representation.dup;
}

/// Convert an array of bytes to a string
string bytesToString(ubyte[] bytes) {
    return cast(string)bytes;
}