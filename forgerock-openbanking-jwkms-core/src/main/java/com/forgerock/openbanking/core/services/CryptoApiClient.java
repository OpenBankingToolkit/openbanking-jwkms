/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.services;

import com.forgerock.openbanking.core.exception.InvalidTokenException;
import com.forgerock.openbanking.core.model.csr.CSRGenerationResponse;
import com.forgerock.openbanking.core.model.csr.CSRImportPemsRequest;
import com.forgerock.openbanking.core.model.SigningRequest;
import com.forgerock.openbanking.core.rest.CreateDetachedJwtResponse;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.web.client.RestTemplate;

import java.text.ParseException;

public interface CryptoApiClient {

    JWK getKey(String appId, String keyId) throws ParseException;

    String getPublicCert(String appId, String keyId);

    String getPrivateCert(String appId, String keyId);

    String signClaims(SigningRequest signingRequest, JWTClaimsSet jwtClaimsSet);

    String signClaims(String issuerId, JWTClaimsSet jwtClaimsSet);

    String signClaims(SigningRequest signingRequest, String issuerId, JWTClaimsSet jwtClaimsSet);

    String signClaims(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, JWTClaimsSet jwtClaimsSet);

    CreateDetachedJwtResponse signPayloadToDetachedJwt(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, String payload);

    CreateDetachedJwtResponse signPayloadToDetachedJwt(SigningRequest signingRequest, String issuerId, String payload);

    String signAndEncryptClaims(JWTClaimsSet jwtClaimsSet, String jwkUri);

    String signAndEncryptClaims(String issuerId, JWTClaimsSet jwtClaimsSet, String jwkUri);

    String signAndEncryptJwtForOBApp(JWTClaimsSet jwtClaimsSet, String obAppId);

    String signAndEncryptJwtForOBApp(String issuerId, JWTClaimsSet jwtClaimsSet, String obAppId);

    SignedJWT decryptJwe(String serializedJwe) throws ParseException;

    SignedJWT decryptJwe(String expectedAudienceId, String serializedJwe) throws ParseException;

    void validateJws(String serializedJws, String expectedIssuerId) throws InvalidTokenException;

    void validateJwsWithExpectedAudience(String serializedJws, String expectedAudienceId, String expectedIssuerId) throws InvalidTokenException;

    void validateJws(String serializedJws, String expectedIssuerId, String jwkUri) throws InvalidTokenException;

    void validateJwsWithJWK(String serializedJws, String expectedIssuerId, String jwk) throws InvalidTokenException;

    void validateJws(String serializedJws, String expectedAudienceId, String expectedIssuerId, String jwkUri)
            throws InvalidTokenException;

    void validateDetachedJWS(String jwsDetachedSignature, Object body, String expectedAudienceId, String expectedIssuerId, String jwkUri)
            throws InvalidTokenException;

    void validateDetachedJWSWithJWK(String jwsDetachedSignature, Object body, String expectedAudienceId, String expectedIssuerId, JWK jwk)
            throws InvalidTokenException;

    SignedJWT verifyAccessToken(String accessTokenBearer)
            throws ParseException, InvalidTokenException;

    CSRGenerationResponse generateCSR(String CN, String OU, String O);

    CSRGenerationResponse importCSRResponse(CSRImportPemsRequest csrImportPemsRequest);

    String exportAsPem(KeyUse keyUse);
}
