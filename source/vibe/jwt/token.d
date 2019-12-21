module vibe.jwt.token;
import vibe.jwt;
import vibe.jwt.helpers;
import vibe.data.json;
import vibe.data.serialization;
import std.base64 : Base64URLNoPadding;
import std.format : format;
import std.datetime;
public import vibe.web.auth;

// Following is some helper functions to make sure the implementation is consistent

private {
    // Little system to generate a random key on app startup

    ubyte[] JWTKey;
    static this() {
        JWTKey = generateKey(32);
    }
}

/**
    Gets the default key for signing tokens
    This key is automatically generated on startup.
*/
string getRandomJWTKey() {
    return b64Encode(JWTKey);
}

/**
    The algorithm for the token
*/
enum Algorithm : string {
    HS256 = "HS256",
    HS384 = "HS384",
    HS512 = "HS512"
}

/**
    A JWT header
*/
struct Header {
    /// The algorithm for the signature
    @name("alg")
    Algorithm algorithm;

    /// Type is generally Json Web Token
    @name("typ")
    string type = "JWT";

    string toString() {
        return serializeToJsonString(this);
    }
}

/**
    A JSON Web Token
*/
class Token {
public @trusted:
    /**
        The header of a JWT Token        
    */
    Header header;

    /**
        The payload of a JWT token
    */
    Json payload;

    /**
        The saved signature of a JWT Token
    */
    string signature;

    this() { }

    /**
        Creates a token instance from an already completed token (used to verify tokens)
    */
    this(string Token) {
        import std.array : split;

        // If the structure is invalid throw an exception        
        if (!validateJWTStructure(Token)) throw new Exception("Invalid JWT structure!");

        // Split from the '.' character, then decode the segments of the token
        string[] parts = Token.split('.');
        header = deserializeJson!Header(parts[0].b64Decode.bytesToString());
        payload = parseJsonString(parts[1].b64Decode.bytesToString());
        signature = parts[2];
    }

    /**
        Creates a new JWT Token
    */
    this(T)(Header header, T payload) {
        this.header = header;
        static if (is(T : Json)) {
            this.payload = payload;
        } else {
            this.payload = serializeToJson!T(payload);
        }
    }

    /**
        Creates a new JWT Token
    */
    this(T)(Header header, T payload, long expiry) {
        this(header, payload);
        this.setExpiry(expiry);
    }
    
    /**
        Creates a new JWT Token with default settings
    */
    this(T)(T payload, long expiry) {
        this(Header(Algorithm.HS256, "JWT"), payload, expiry);
    }
    
    /**
        Creates a new JWT Token with default settings
    */
    this(T)(T payload) {
        this(Header(Algorithm.HS256, "JWT"), payload);
    }

    /// Sets the expiry time
    void setExpiry(long time) {
        payload["exp"] = Json(time);
    }

    /// Sets the "not before" time
    void setNotBefore(long time) {
        payload["nbf"] = Json(time);
    }

    /// Gets the expiry time, throws exception if not found
    long getExpiry(long time) {
        if ("exp" !in payload || payload["exp"].type == Json.Type.undefined) throw new TokenFieldMissingException("exp");
        return payload["exp"].opt!long(long.min);
    }

    /// Gets the not before time, throws exception if not found
    long getNotBefore(long time) {
        if ("nbf" !in payload || payload["nbf"].type == Json.Type.undefined) throw new TokenFieldMissingException("nbf");
        return payload["nbf"].opt!long(long.min);
    }

    /**
        Sign the JWT Token
    */
    string sign(ubyte[] secret) {
        signature = genSignature(header, payload, secret);
        return this.toString();
    }

    /**
        Sign the JWT Token with the randomly generated default key
    */
    string sign(string key) {
        return sign(cast(ubyte[])key);
    }

    /**
        Sign the JWT Token with the randomly generated default key
    */
    string sign() {
        return sign(getRandomJWTKey());
    }

    /**
        Verifies that the token is valid at current time and that it hasn't been tampered with
    */
    void verify(ubyte[] secret) {

        // First check the signature
        if (!verifySignature(this, secret)) throw new TokenSigException();

        // Get the current time, used in calculations
        immutable(long) currentTime = Clock.currStdTime();

        // Make sure that the expiry time actually exists.
        if (payload["exp"].type != Json.Type.undefined) {

            // Get EXP time, if not available, set to smallest possible value.
            immutable(long) expiryTime = payload["exp"].opt!long(long.min);

            // The token has expired.
            if (currentTime >= expiryTime) throw new TokenExpiredException();
        }

        // Make sure that the not-before time actually exists.
        if (payload["nbf"].type != Json.Type.undefined) {
            
            // Get NBF time, if not available, set to smallest possible value.
            immutable(long) nbfTime = payload["nbf"].opt!long(long.min);

            // The token has expired.
            if (currentTime < nbfTime) throw new TokenNotBeforeException();
        }
    }

    /**
        Verifies that the token isn't expired and hasn't been tampered with with the specified key
    */
    void verify(string key) {
        verify(key);
    }

    /**
        Verifies that the token isn't expired and hasn't been tampered with with the randomly generated default key
    */
    void verify() {
        verify(getRandomJWTKey());
    }
    
    /** 
        Output the final JWT token
    */
    override
    string toString() {
        // return the fo
        return "%s.%s.%s".format(header.toString().b64Encode(), payload.toString().b64Encode(), signature);
    }
}