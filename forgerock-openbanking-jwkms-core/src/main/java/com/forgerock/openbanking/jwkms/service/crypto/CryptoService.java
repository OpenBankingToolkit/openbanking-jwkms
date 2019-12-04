/**
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
package com.forgerock.openbanking.jwkms.service.crypto;

import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import com.forgerock.openbanking.jwt.model.CreateDetachedJwtResponse;
import com.forgerock.openbanking.jwt.model.SigningRequest;
import com.forgerock.openbanking.jwt.model.ValidDetachedJwtResponse;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.text.ParseException;

/**
 * Sign/validate JWS and encrypt/decrypt JWE for an application
 */
public interface CryptoService {

    /**
     * Get the public JWKs for an application
     * @param application the application
     * @return the public JWKs
     */
    JWKSet getPublicJwks(Application application);

    /**
     * Get the transport keyspublic JWKs for an application
     * @param application the application
     * @return the public JWKs
     */
    JWKSet getTransportPublicJwks(Application application);

    /**
     * Sign claims on behalf of an application
     * @param issuerId the issuer ID
     * @param claimsSet the claims
     * @param application the application
     * @param includeKey
     * @return the JWS
     */
    SignedJWT sign(String issuerId, JWTClaimsSet claimsSet, Application application, Boolean includeKey);

    /**
     * Sign claims on behalf of an application
     * @param signingRequest the signing request options
     * @param issuerId the issuer ID
     * @param payload the payload
     * @param application the application
     * @return the JWS
     */
    CreateDetachedJwtResponse signPayloadToDetachedJwt(SigningRequest signingRequest, String issuerId, String payload, Application application);
    /**
     * Encrypt and sign claims on behalf of an application
     * @param claimsSet the claims
     * @param jwkForEncryption the public enc key of the dest app
     * @param applicationForSigning the application signing
     * @return JWE(JWS)
     * @throws JOSEException
     */
    EncryptedJWT signAndEncrypt(String issuerId, JWTClaimsSet claimsSet,
                                RSAKey jwkForEncryption, Application applicationForSigning, Boolean includeKey)
            throws JOSEException;

    /**
     * Decrypt a JWE(JWS) for an application managed by our Jwk MS
     * @param encryptedJWT the JWE
     * @param application the internal app
     * @return JWS validated
     */
    SignedJWT decrypt(EncryptedJWT encryptedJWT, Application application);

    /**
     * Validate a JWS
     * @param signedJWT JWS to validate
     * @param application the application which wants to verify this JWS
     * @throws InvalidTokenException the JWS is invalid
     * @throws ParseException the JWS format is invalid.
     */
    void validate(SignedJWT signedJWT, String expectedAudienceId, Application application)
            throws InvalidTokenException, ParseException;

    /**
     * Validate a JWS
     * @param signedJWT JWS to validate
     * @param issuerId the application issuer ID
     * @param jwkUri the application jwk uri
     * @throws InvalidTokenException the JWS is invalid
     * @throws ParseException the JWS format is invalid.
     */
    void validate(SignedJWT signedJWT, String issuerId, String jwkUri)
            throws InvalidTokenException, ParseException, IOException;

    /**
     * Validate a JWS
     * @param signedJWT JWS to validate
     * @param issuerId the application issuer ID
     * @param jwk the application jwk
     * @throws InvalidTokenException the JWS is invalid
     * @throws ParseException the JWS format is invalid.
     */
    void validate(SignedJWT signedJWT, String issuerId, JWK jwk)
            throws InvalidTokenException;
    /**
     * Validate a Detached JWS
     * @param signedJWT JWS to validate
     * @param issuerId the application issuer ID
     * @param jwkUri the application jwk uri
     * @throws InvalidTokenException the JWS is invalid
     * @throws ParseException the JWS format is invalid.
     */
    ValidDetachedJwtResponse validateDetachedJwS(SignedJWT signedJWT, String issuerId, String jwkUri)
            throws ParseException, IOException;

    /**
     * Validate a Detached JWS
     * @param signedJWT JWS to validate
     * @param issuerId the application issuer ID
     * @param jwk the application jwk
     * @throws InvalidTokenException the JWS is invalid
     * @throws ParseException the JWS format is invalid.
     */
    ValidDetachedJwtResponse validateDetachedJwSWithJWK(SignedJWT signedJWT, String issuerId, String jwk)
            throws ParseException;

    /**
     * Validate a Detached JWS
     * @param signedJWT JWS to validate
     * @param issuerId the application issuer ID
     * @throws InvalidTokenException the JWS is invalid
     * @throws ParseException the JWS format is invalid.
     */
    ValidDetachedJwtResponse validateDetachedJwS(SignedJWT signedJWT, String issuerId)
            throws ParseException;
}
