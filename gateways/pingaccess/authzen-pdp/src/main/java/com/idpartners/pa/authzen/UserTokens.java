package com.idpartners.pa.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * How X-User-Token is read. Its claims feed user_scope and the login gate, which is
 * exactly what a forged one would walk through, so when user_token_jwks_url is set
 * the token is verified (signature, exp, nbf, iss, aud; alg none refused) and one
 * that fails yields no claims at all: the gates it feeds close rather than open.
 * Unset, it is decoded only, as the Kong plugin does, and configure() says so.
 *
 * <p>The access token is not handled here. PingAccess validates it itself, before any
 * rule runs, when the application is protected; the rule reads what PingAccess
 * established.
 */
final class UserTokens {
    private static final Logger log = LoggerFactory.getLogger(UserTokens.class);

    interface Reader {
        /** The token's claims, or null when it is unusable. */
        ObjectNode claims(String token);
    }

    private UserTokens() {
    }

    static Reader decodeOnly() {
        return Jwt::claims;
    }

    static Reader verified(String jwksUrl, String issuer, String audience) {
        JwtConsumerBuilder b = new JwtConsumerBuilder()
            .setVerificationKeyResolver(new HttpsJwksVerificationKeyResolver(new HttpsJwks(jwksUrl)))
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
            .setAllowedClockSkewInSeconds(30);
        if (issuer != null && !issuer.isEmpty()) {
            b.setExpectedIssuer(issuer);
        }
        if (audience != null && !audience.isEmpty()) {
            b.setExpectedAudience(audience);
        } else {
            b.setSkipDefaultAudienceValidation();
        }
        JwtConsumer consumer = b.build();
        return token -> {
            if (token == null) {
                return null;
            }
            try {
                JsonNode n = Json.parse(consumer.processToClaims(token).getRawJson());
                return n instanceof ObjectNode ? (ObjectNode) n : null;
            } catch (InvalidJwtException e) {
                log.warn("X-User-Token rejected: {}", e.getMessage());
                return null;
            }
        };
    }
}
