/**
 * Copyright 2019 ForgeRock AS.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.forgerock.openbanking.jwkms.service.token;

import com.forgerock.openbanking.constants.OpenBankingConstants;
import com.forgerock.openbanking.core.config.ApplicationConfiguration;
import com.forgerock.openbanking.core.utils.JwtUtils;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import com.forgerock.openbanking.jwt.model.SigningRequest;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Set;

/**
 * A service for tokens using in our RCS flow
 */
@Service
public class TokenService {
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenService.class);

    /**
     * Validate a JWS signed by a remote party to the current app
     *
     * @param from the remote configuration of the party that signed the JWS
     * @param to   the configuration of the current app. Can be null if only a valid token is required.
     * @param jws  A JWS signed
     * @throws InvalidTokenException invalid JWT if the JWT is invalid. It can be because of the signature, the
     *                               expiration time, the issuer or the audience.
     * @throws ParseException
     */
    public void validateToken(SignedJWT jws, ApplicationConfiguration from, ApplicationConfiguration to)
            throws InvalidTokenException {
        validateToken(jws, from, to, (jwt) -> jwt.getJWTClaimsSet().getIssuer(), null);
    }

    public void validateDetachedToken(SignedJWT jws, ApplicationConfiguration from, ApplicationConfiguration to)
            throws InvalidTokenException {
        validateToken(jws, from, to,
                (jwt) -> (String) jwt.getHeader().getCustomParam(OpenBankingConstants.OBJwtHeaderClaims.OB_ISS),
                SigningRequest.DEFAULT_SUPPORT_CRIT_CLAIMS
        );
    }

    private void validateToken(SignedJWT jws, ApplicationConfiguration from, ApplicationConfiguration to,
                               GetJWTIssuer getJWTIssuer, Set<String> defCritHeaders)
            throws InvalidTokenException {
        LOGGER.debug("Validate token {} from {} to {}", jws.serialize(), from, to);

        if (!validateSignature(jws, from.getJwkSet(), defCritHeaders)) {
            LOGGER.debug("Invalid signature for jws {}", jws);
            throw new InvalidTokenException("Invalid signature");
        }
        if (isJwtExpired(jws)) {
            LOGGER.debug("JWS expired {}", jws);
            throw new InvalidTokenException("JWT expired");
        }
        if (from.getIssuerID() != null && !validateIssuer(jws, from.getIssuerID(), getJWTIssuer)) {
            LOGGER.debug("Invalid issuer for {}", jws);
            throw new InvalidTokenException("Invalid issuer.");
        }
        if (to != null && !validateAudience(jws, to.getIssuerID())) {
            LOGGER.debug("Invalid audience for {}", jws);
            throw new InvalidTokenException("Invalid audience.");
        }
    }

    /**
     * Validate the issuer
     *
     * @param jwt      a JWT
     * @param issuerId the issuer expected
     * @return true if the issuer is the one excepted.
     * @throws InvalidTokenException
     */
    public boolean validateIssuer(JWT jwt, String issuerId, GetJWTIssuer getJWTIssuer ) throws InvalidTokenException {
        try {
            LOGGER.debug("Expected issuer {} and jws issuer{}", issuerId, jwt.getJWTClaimsSet().getIssuer());
            return issuerId.equals(
                    getJWTIssuer.getIssuer(jwt));
        } catch (ParseException e) {
            throw new InvalidTokenException(e);
        }
    }

    /**
     * Validate the audience
     *
     * @param jwt        a jwt
     * @param audienceId the audience expected
     * @return true if the audience is the one excepted.
     * @throws InvalidTokenException
     */
    public boolean validateAudience(JWT jwt, String audienceId) throws InvalidTokenException {
        try {
            LOGGER.debug("Expected audience id {} and jws audience", audienceId, jwt.getJWTClaimsSet().getAudience());
            return jwt.getJWTClaimsSet().getAudience().contains(audienceId);
        } catch (ParseException e) {
            throw new InvalidTokenException(e);
        }
    }

    /**
     * Check if the JWT is not expired.
     *
     * @param jwt a JWT
     * @return true if the JWT is still valid
     * @throws InvalidTokenException
     */
    public boolean isJwtExpired(JWT jwt) throws InvalidTokenException {
        try {
            LOGGER.debug("JWT expired time is {} and current time is {}",
                    jwt.getJWTClaimsSet().getExpirationTime(), Calendar.getInstance().getTime());
            if (jwt.getJWTClaimsSet().getExpirationTime() != null) {
                return Calendar.getInstance().getTime().after(jwt.getJWTClaimsSet().getExpirationTime());
            }
        } catch (ParseException e) {
            LOGGER.error("Can't parse the claims of jwt {}", jwt, e);
            throw new InvalidTokenException(e);
        }
        return false;
    }


    /**
     * Validate a signature in general
     *
     * @param jws       A JWS you want to check
     * @param jwkSetMap the JWKS public of the party that has signed the JWT.
     * @return true if the JWS can be verified with one of the JWK contained in the JWKs list.
     */
    public boolean  validateSignature(SignedJWT jws, JWKSet jwkSetMap, Set<String> defCritHeaders) {
        JWK jwk = jwkSetMap.getKeyByKeyId(jws.getHeader().getKeyID());
        if (jwk == null) {
            LOGGER.warn("Couldn't find the JWK corresponding to kid {} in jwk set", jws.getHeader().getKeyID(),
                    jwkSetMap);
            throw new IllegalArgumentException("Failed to find JWK for the following kid='"
                    + jws.getHeader().getKeyID() + "'");
        }

        try {
            JWSVerifier verifier = getJwsVerifier(defCritHeaders, jwk);
            byte[] signingInput;

            if (jws.getHeader().getCustomParam("b64") != null
                    && !(Boolean) jws.getHeader().getCustomParam("b64")) {
                signingInput = JwtUtils.getSingingInputNonEncodedPayload(jws.getHeader(), jws.getPayload().toString());
            } else {
                signingInput = jws.getSigningInput();
            }

            return verifier.verify(jws.getHeader(), signingInput, jws.getSignature());
        } catch (JOSEException e) {
            LOGGER.error("Failed to verify jws='{}' signature", jws, e);
            throw new IllegalArgumentException("Failed to verify jws='" + jws + "' signature", e);
        } catch (ParseException e) {
            LOGGER.error("Failed to read claims from jws='{}'", jws, e);
            throw new IllegalArgumentException("Failed to read claims from jws='" + jws + "'", e);
        } catch (UnsupportedEncodingException e) {
            LOGGER.error("Failed to encode payload and header in byte. jws={}", jws, e);
            throw new RuntimeException("Failed to encode payload and header in byte. jws='" + jws + "'", e);
        }
    }

    private JWSVerifier getJwsVerifier(Set<String> defCritHeaders, JWK jwk) throws JOSEException {
        JWSVerifier verifier;
        if (KeyType.RSA == jwk.getKeyType()) {
            LOGGER.debug("jwk found is a RSA key");
            RSAKey signingRsaKey = (RSAKey) jwk;
            verifier = new RSASSAVerifier(signingRsaKey.toRSAPublicKey(), defCritHeaders);
        } else if (KeyType.EC == jwk.getKeyType()) {
            LOGGER.debug("jwk found is a EC key");
            ECKey signingECKey = (ECKey) jwk;
            verifier = new ECDSAVerifier(signingECKey.toECPublicKey(), defCritHeaders);
        } else if (KeyType.OCT == jwk.getKeyType()) {
            LOGGER.debug("jwk found is a OCT key");
            OctetSequenceKey octetSequenceKey = (OctetSequenceKey) jwk;
            verifier = new MACVerifier(octetSequenceKey.toByteArray(), defCritHeaders);
        } else {
            LOGGER.debug("Format of jwk='{}' not implemented", jwk);
            throw new IllegalArgumentException("Format of jwk='" + jwk + "' not implemented");
        }
        return verifier;
    }

    public interface GetJWTIssuer {
        String getIssuer(JWT jwt) throws ParseException;
    }
}

