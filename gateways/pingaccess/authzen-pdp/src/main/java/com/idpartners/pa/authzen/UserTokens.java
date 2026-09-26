package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jose4j.http.SimpleGet;
import org.jose4j.http.SimpleResponse;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * How X-User-Token is read. Its claims feed user_scope and the login gate, which is
 * exactly what a forged one would walk through, so it is verified against
 * user_token_jwks_url (signature, exp, nbf, iss, aud and sub; alg none refused) and one
 * that fails yields no claims at all: the gates it feeds close rather than open. Without
 * a JWKS the token is ignored, unless allow_insecure says to decode it anyway.
 *
 * <p>The access token is not handled here. PingAccess validates it itself, before any
 * rule runs, when the application is protected; the rule reads what PingAccess
 * established.
 */
final class UserTokens {
    private static final Logger log = LoggerFactory.getLogger(UserTokens.class);
    /** The JWKS fetch: one deadline over the whole exchange, and a small cap; a key set is a few KiB. */
    static final int JWKS_TIMEOUT_MS = 3000;
    static final int JWKS_MAX_BYTES = 256 * 1024;
    /** Seconds a key set is believed when the server says nothing about caching. */
    static final long JWKS_CACHE_SECONDS = 300;
    /** Seconds the last good key set is kept while its refresh fails. */
    static final long JWKS_KEEP_ON_ERROR_SECONDS = 900;
    /** Milliseconds between refreshes forced by an unknown kid: a stream of made-up kids is one fetch, not one each. */
    static final long JWKS_REFETCH_MS = 30_000;

    interface Reader {
        /** The token's claims, or null when it is unusable. */
        ObjectNode claims(String token);
    }

    private UserTokens() {
    }

    /** No JWKS and no permission to take the token on trust: it opens nothing. */
    static Reader ignored() {
        return token -> null;
    }

    /** allow_insecure without a JWKS: decoded, not verified, as the configure-time warning says. */
    static Reader decodeOnly() {
        return Jwt::claims;
    }

    static Reader verified(String jwksUrl, String issuer, String audience, Transport transport, boolean verifyTls) {
        HttpsJwks jwks = new HttpsJwks(jwksUrl);
        jwks.setSimpleHttpGet(new TransportGet(transport, verifyTls));
        jwks.setDefaultCacheDuration(JWKS_CACHE_SECONDS);
        jwks.setRetainCacheOnErrorDuration(JWKS_KEEP_ON_ERROR_SECONDS);
        jwks.setRefreshReprieveThreshold(JWKS_REFETCH_MS);
        JwtConsumerBuilder b = new JwtConsumerBuilder()
            .setVerificationKeyResolver(new HttpsJwksVerificationKeyResolver(jwks))
            .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256,
                AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384,
                AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512,
                AlgorithmIdentifiers.RSA_USING_SHA256,
                AlgorithmIdentifiers.RSA_USING_SHA384,
                AlgorithmIdentifiers.RSA_USING_SHA512,
                AlgorithmIdentifiers.RSA_PSS_USING_SHA256,
                AlgorithmIdentifiers.RSA_PSS_USING_SHA384,
                AlgorithmIdentifiers.RSA_PSS_USING_SHA512)
            .setRequireExpirationTime()
            .setRequireSubject()
            .setAllowedClockSkewInSeconds(30);
        if (issuer != null && !issuer.isEmpty()) {
            b.setExpectedIssuer(issuer);
        }
        if (audience != null && !audience.isEmpty()) {
            b.setExpectedAudience(true, audience);
        } else {
            // Only under allow_insecure: validate() requires an audience otherwise.
            b.setSkipDefaultAudienceValidation();
        }
        JwtConsumer consumer = b.build();
        return token -> {
            if (token == null) {
                return null;
            }
            try {
                return Json.parseObject(consumer.processToClaims(token).getRawJson().getBytes(StandardCharsets.UTF_8));
            } catch (InvalidJwtException e) {
                // jose4j's message quotes the token's claims; the log gets why, not whose.
                log.warn("X-User-Token rejected: {}", reason(e));
                return null;
            }
        };
    }

    /** A rejection's cause in a few words, from jose4j's error codes; never the token's content. */
    static String reason(InvalidJwtException e) {
        for (Map.Entry<Integer, String> r : REASONS.entrySet()) {
            if (e.hasErrorCode(r.getKey())) {
                return r.getValue();
            }
        }
        return "not a verifiable token (unsigned, malformed, an algorithm not allowed, or no key for its kid)";
    }

    private static final Map<Integer, String> REASONS = new LinkedHashMap<>();

    static {
        REASONS.put(ErrorCodes.EXPIRED, "expired");
        REASONS.put(ErrorCodes.EXPIRATION_MISSING, "no exp");
        REASONS.put(ErrorCodes.NOT_YET_VALID, "not yet valid");
        REASONS.put(ErrorCodes.AUDIENCE_INVALID, "wrong audience");
        REASONS.put(ErrorCodes.AUDIENCE_MISSING, "no audience");
        REASONS.put(ErrorCodes.ISSUER_INVALID, "wrong issuer");
        REASONS.put(ErrorCodes.ISSUER_MISSING, "no issuer");
        REASONS.put(ErrorCodes.SUBJECT_MISSING, "no subject");
        REASONS.put(ErrorCodes.SIGNATURE_INVALID, "signature invalid");
    }

    /**
     * jose4j's JWKS fetch, over the rule's own transport: one deadline over the whole
     * exchange and a size cap, where jose4j's own client has 20-second connect and read
     * timeouts, three retries and no cap. jose4j calls it while holding its refresh
     * lock, which the deadline keeps short.
     */
    static final class TransportGet implements SimpleGet {
        private final Transport transport;
        private final boolean verifyTls;

        TransportGet(Transport transport, boolean verifyTls) {
            this.transport = transport;
            this.verifyTls = verifyTls;
        }

        @Override
        public SimpleResponse get(String location) throws IOException {
            Transport.Response r;
            try {
                r = transport.send(new Transport.Request("GET", location, Map.of("Accept", "application/json"), null,
                    JWKS_TIMEOUT_MS, verifyTls, JWKS_MAX_BYTES));
            } catch (Transport.Refused e) {
                throw new IOException("JWKS fetch refused: " + e.getMessage(), e);
            }
            if (r.status() != 200) {
                throw new IOException("JWKS fetch returned " + r.status());
            }
            return new SimpleResponse() {
                @Override
                public int getStatusCode() {
                    return r.status();
                }

                @Override
                public String getStatusMessage() {
                    return "";
                }

                @Override
                public Collection<String> getHeaderNames() {
                    return r.headers() == null ? List.of() : new ArrayList<>(r.headers().keySet());
                }

                @Override
                public List<String> getHeaderValues(String name) {
                    String v = r.header(name);
                    return v == null ? List.of() : List.of(v);
                }

                @Override
                public String getBody() {
                    return r.body() == null ? "" : new String(r.body(), StandardCharsets.UTF_8);
                }
            };
        }
    }
}
