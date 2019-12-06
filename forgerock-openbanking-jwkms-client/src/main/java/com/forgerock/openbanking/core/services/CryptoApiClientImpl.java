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
package com.forgerock.openbanking.core.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.openbanking.core.model.ValidJwtResponse;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import com.forgerock.openbanking.jwt.model.CreateDetachedJwtResponse;
import com.forgerock.openbanking.jwt.model.SigningRequest;
import com.forgerock.openbanking.jwt.model.ValidDetachedJwtResponse;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.text.ParseException;

@Service
public class CryptoApiClientImpl implements CryptoApiClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoApiClientImpl.class);
    
    @Value("${jwkms.root}")
    private String jwkmsRoot;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public JWK getKey(String appId, String keyId) throws ParseException {
        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/key/" + keyId);
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<String> entity = restTemplate.exchange(uri, HttpMethod.PUT, null, ptr);
        return JWK.parse(entity.getBody());
    }

    public String getPublicCert(String appId, String keyId) {
        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/key/" + keyId + "/certificate/public/");
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<String> entity = restTemplate.exchange(uri, HttpMethod.PUT, null, ptr);
        return entity.getBody();
    }

    public String getPrivateCert(String appId, String keyId) {
        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/key/" + keyId + "/certificate/private/");
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<String> entity = restTemplate.exchange(uri, HttpMethod.PUT, null, ptr);
        return entity.getBody();
    }

    /**
     * Sign a set of claims
     * @param jwtClaimsSet
     * @return JWS serialized
     */
    @Override
    public String signClaims(SigningRequest signingRequest, JWTClaimsSet jwtClaimsSet)  {
        return signClaims(restTemplate, signingRequest, null, jwtClaimsSet);
    }
    /**
     * Sign a set of claims
     * @param jwtClaimsSet
     * @return JWS serialized
     */
    @Override
    public String signClaims(String issuerId, JWTClaimsSet jwtClaimsSet, boolean includeKey) {
        return signClaims(restTemplate, null, issuerId, jwtClaimsSet.toString(), "signClaims", includeKey);
    }

    /**
     * Sign a set of claims
     * @param jwtClaimsSet
     * @return JWS serialized
     */
    @Override
    public String signClaims(SigningRequest signingRequest, String issuerId, JWTClaimsSet jwtClaimsSet) {
        return signClaims(restTemplate, signingRequest, issuerId, jwtClaimsSet);
    }
    /**
     * Sign a set of claims
     * @param jwtClaimsSet
     * @return JWS serialized
     */
    @Override
    public String signClaims(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, JWTClaimsSet jwtClaimsSet) {
        return signClaims(restTemplate, signingRequest, issuerId, jwtClaimsSet.toString(), "signClaims", false);
    }

    @Override
    public CreateDetachedJwtResponse signPayloadToDetachedJwt(SigningRequest signingRequest, String issuerId, String payload) {
        return signPayloadToDetachedJwt(restTemplate, signingRequest, issuerId, payload);
    }

    @Override
    public CreateDetachedJwtResponse signPayloadToDetachedJwt(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, String payload) {
        return signPayloadToDetachedJwt(restTemplate, signingRequest, issuerId, payload, "signPayloadToDetachedJwt");
    }


    private CreateDetachedJwtResponse signPayloadToDetachedJwt(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, String payload, String path)  {
        HttpHeaders headers = new HttpHeaders();
        if (issuerId != null) {
            headers.add("issuerId", issuerId);
        }
        if (signingRequest != null) {
            try {
                headers.add("signingRequest", objectMapper.writeValueAsString(signingRequest));
            } catch (JsonProcessingException e) {
                LOGGER.error("Can't serialise signing request '{}' into a string", signingRequest, e);
            }
        }
        HttpEntity<String> request = new HttpEntity<>(payload.toString(), headers);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sign claims {}", payload);
        }

        return restTemplate.postForObject(jwkmsRoot + "api/crypto/" + path, request, CreateDetachedJwtResponse.class);
    }

    private String signClaims(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, String payload, String path, boolean includeKey)  {
        HttpHeaders headers = new HttpHeaders();
        if (issuerId != null) {
            headers.add("issuerId", issuerId);
        }
        if (includeKey) {
            headers.add("includeKey", "true");
        }

        if (signingRequest != null) {
            try {
                headers.add("signingRequest", objectMapper.writeValueAsString(signingRequest));
            } catch (JsonProcessingException e) {
                LOGGER.error("Can't serialise signing request '{}' into a string", signingRequest, e);
            }
        }
        HttpEntity<String> request = new HttpEntity<>(payload, headers);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sign claims {}", payload);
        }

        return restTemplate.postForObject(jwkmsRoot + "api/crypto/" + path, request, String.class);
    }
    /**
     * Sign and encrypt claims for an app not yet referenced in our system
     * @param jwtClaimsSet the claims
     * @param jwkUri the JWK uri of the external app
     * @return the JWE(JWS) serialized
     */
    @Override
    public String signAndEncryptClaims(JWTClaimsSet jwtClaimsSet, String jwkUri) {
        return signAndEncryptClaims(null, jwtClaimsSet, jwkUri);
    }

    /**
     * Sign and encrypt claims for an app not yet referenced in our system
     * @param jwtClaimsSet the claims
     * @param jwkUri the JWK uri of the external app
     * @return the JWE(JWS) serialized
     */
    @Override
    public String signAndEncryptClaims(String issuerId, JWTClaimsSet jwtClaimsSet, String jwkUri) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwkUri", jwkUri);
        if (issuerId != null) {
            headers.add("issuerId", issuerId);
        }
        HttpEntity<String> request = new HttpEntity<>(jwtClaimsSet.toString(), headers);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sign claims {} and encrypt jws for {}", jwtClaimsSet, jwkUri);
        }
        return restTemplate.postForObject(jwkmsRoot + "api/crypto/signAndEncryptClaims", request, String.class);
    }

    /**
     * Sign and encrypt claims for another app
     * @param jwtClaimsSet the claims
     * @param obAppId the app id for which the JWE is for.
     * @return the JWE(JWS) serialized
     */
    @Override
    public String signAndEncryptJwtForOBApp(JWTClaimsSet jwtClaimsSet, String obAppId) {
        return signAndEncryptJwtForOBApp(null, jwtClaimsSet, obAppId);
    }

    /**
     * Sign and encrypt claims for another app
     * @param jwtClaimsSet the claims
     * @param obAppId the app id for which the JWE is for.
     * @return the JWE(JWS) serialized
     */
    @Override
    public String signAndEncryptJwtForOBApp(String issuerId, JWTClaimsSet jwtClaimsSet, String obAppId) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("obAppId", obAppId);
        if (issuerId != null) {
            headers.add("issuerId", issuerId);
        }
        HttpEntity<String> request = new HttpEntity<>(jwtClaimsSet.toString(), headers);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sign claims {} and encrypt jws for {}", jwtClaimsSet, obAppId);
        }
        return restTemplate.postForObject(jwkmsRoot + "api/crypto/signAndEncryptJwtForOBApp", request, String.class);
    }

    /**
     * Decrypt a JWE received for the current app
     * @param serializedJwe the jwe serialized
     * @return the JWS inside the JWE (the JWS is already validated)
     * @throws ParseException can't parse the JWE
     */
    @Override
    public SignedJWT decryptJwe(String serializedJwe) throws ParseException {
        return decryptJwe(null, serializedJwe);
    }

    /**
     * Decrypt a JWE received for the current app
     * @param serializedJwe the jwe serialized
     * @return the JWS inside the JWE (the JWS is already validated)
     * @throws ParseException can't parse the JWE
     */
    @Override
    public SignedJWT decryptJwe(String expectedAudienceId, String serializedJwe) throws ParseException {
        HttpHeaders headers = new HttpHeaders();
        if (expectedAudienceId != null) {
            headers.add("expectedAudienceId", expectedAudienceId);
        }
        HttpEntity<String> request = new HttpEntity<>(serializedJwe, headers);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Decrypt jwe {}", serializedJwe);
        }
        return SignedJWT.parse(restTemplate.postForObject(jwkmsRoot + "api/crypto/decryptJwe", request, String.class));
    }

    /**
     * Validate a JWS
     * @param serializedJws the jws serialized
     * @param expectedIssuerId the expected issuer ID
     * @throws InvalidTokenException the JWS is invalid
     */
    @Override
    public SignedJWT validateJws(String serializedJws, String expectedIssuerId) throws InvalidTokenException, ParseException {
        return validateJwsWithExpectedAudience(serializedJws, null, expectedIssuerId);
    }

    /**
     * Validate a JWS
     * @param serializedJws the jws serialized
     * @param expectedIssuerId the expected issuer ID
     * @throws InvalidTokenException the JWS is invalid
     * @return
     */
    @Override
    public SignedJWT validateJwsWithExpectedAudience(String serializedJws, String expectedAudienceId, String expectedIssuerId) throws InvalidTokenException, ParseException {
        HttpHeaders headers = new HttpHeaders();
        headers.add("expectedIssuerId", expectedIssuerId);
        if (expectedAudienceId != null) {
            headers.add("expectedAudienceId", expectedAudienceId);
        }
        HttpEntity<String> request = new HttpEntity<>(serializedJws, headers);
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Validate jws {} with expectedIssuerId {}", serializedJws, expectedIssuerId);
        }
        ValidJwtResponse response = restTemplate.postForObject(jwkmsRoot + "api/crypto/validateJws", request,
                ValidJwtResponse.class);
        if (!response.isValid) {
            throw new InvalidTokenException(response.message);
        }
        if (response.getOriginalJWS() != null) {
            return SignedJWT.parse(response.getOriginalJWS());
        }
        return null;
    }

    /**
     * Validate a JWS
     * @param serializedJws the jws serialized
     * @param expectedIssuerId the expected issuer ID
     * @param jwkUri the issuer jwk URI
     * @throws InvalidTokenException the JWS is invalid
     */
    @Override
    public SignedJWT validateJws(String serializedJws, String expectedIssuerId, String jwkUri) throws InvalidTokenException, ParseException {
        return validateJws(serializedJws, null, expectedIssuerId, jwkUri);
    }


    @Override
    public SignedJWT validateJwsWithJWK(String serializedJws, String expectedIssuerId, String jwk) throws InvalidTokenException, ParseException {
        HttpHeaders headers = new HttpHeaders();
        if (expectedIssuerId != null) {
            headers.add("expectedIssuerId", expectedIssuerId);
        }
        headers.add("jwk", jwk);
        HttpEntity<String> request = new HttpEntity<>(serializedJws, headers);
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Validate jws {} with expectedIssuerId {}", serializedJws, expectedIssuerId);
        }
        try {
            ValidJwtResponse response = restTemplate.exchange(jwkmsRoot + "api/crypto/validateJwsWithJWK", HttpMethod.POST, request,
                    ValidJwtResponse.class).getBody();
            if (!response.isValid) {
                throw new InvalidTokenException(response.message);
            }
            if (response.getOriginalJWS() != null) {
                return SignedJWT.parse(response.getOriginalJWS());
            }
            return null;
        } catch (HttpClientErrorException e) {
            LOGGER.debug("Could not validate jws {} because of an http error {}", serializedJws, e.getResponseBodyAsString(), e);
            throw new InvalidTokenException(e.getResponseBodyAsString());
        }
    }


    /**
     * Validate a JWS
     * @param serializedJws the jws serialized
     * @param expectedIssuerId the expected issuer ID
     * @param jwkUri the issuer jwk URI
     * @throws InvalidTokenException the JWS is invalid
     */
    @Override
    public SignedJWT validateJws(String serializedJws, String expectedAudienceId, String expectedIssuerId, String jwkUri)
            throws InvalidTokenException, ParseException {
        HttpHeaders headers = new HttpHeaders();
        if (expectedIssuerId != null) {
            headers.add("expectedIssuerId", expectedIssuerId);
        }
        headers.add("jwkUri", jwkUri);
        HttpEntity<String> request = new HttpEntity<>(serializedJws, headers);
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Validate jws {} with expectedIssuerId {}", serializedJws, expectedIssuerId);
        }
        try {
            ValidJwtResponse response = restTemplate.exchange(jwkmsRoot + "api/crypto/validateJwsWithJwkUri", HttpMethod.POST, request,
                    ValidJwtResponse.class).getBody();
            if (!response.isValid) {
                throw new InvalidTokenException(response.message);
            }
            if (response.getOriginalJWS() != null) {
                return SignedJWT.parse(response.getOriginalJWS());
            }
            return null;
        } catch (HttpClientErrorException e) {
            LOGGER.debug("Could not validate jws {} because of an http error {}", serializedJws, e.getResponseBodyAsString(), e);
            throw new InvalidTokenException(e.getResponseBodyAsString());
        }
    }

    @Override
    public ValidDetachedJwtResponse validateDetachedJWS(String jwsDetachedSignature, Object body, String expectedAudienceId, String expectedIssuerId, String jwkUri)
            throws InvalidTokenException, ParseException {
        HttpHeaders headers = new HttpHeaders();
        if (expectedIssuerId != null) {
            headers.add("expectedIssuerId", expectedIssuerId);
        }
        headers.add("jwkUri", jwkUri);
        headers.add("x-jws-signature", jwsDetachedSignature);
        HttpEntity<Object> request = new HttpEntity<>(body, headers);
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Validate detached jws {} with body with expectedIssuerId {}",jwsDetachedSignature, body, expectedIssuerId);
        }

        try {
            ValidDetachedJwtResponse response = restTemplate.exchange(jwkmsRoot + "api/crypto/validateDetachedJWSWithJwkUri", HttpMethod.POST, request,
                    ValidDetachedJwtResponse.class).getBody();
            if (!response.isValid) {
                throw new InvalidTokenException(response.message);
            }
            return response;
        } catch (HttpClientErrorException e) {
            LOGGER.debug("Could not validate jws {} because of an http error {}", body, e.getResponseBodyAsString(), e);
            throw new InvalidTokenException(e.getResponseBodyAsString());
        }
    }

    @Override
    public ValidDetachedJwtResponse validateDetachedJWSWithJWK(String jwsDetachedSignature, Object body, String expectedAudienceId, String expectedIssuerId, JWK jwk)
            throws InvalidTokenException {
        HttpHeaders headers = new HttpHeaders();
        if (expectedIssuerId != null) {
            headers.add("expectedIssuerId", expectedIssuerId);
        }
        headers.add("jwk", jwk.toJSONString());
        headers.add("x-jws-signature", jwsDetachedSignature);
        HttpEntity<Object> request = new HttpEntity<>(body, headers);
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Validate detached jws {} with body with expectedIssuerId {}",jwsDetachedSignature, body, expectedIssuerId);
        }

        try {
            ValidDetachedJwtResponse response = restTemplate.exchange(jwkmsRoot + "api/crypto/validateDetachedJWSWithJWK", HttpMethod.POST, request,
                    ValidDetachedJwtResponse.class).getBody();
            if (!response.isValid) {
                throw new InvalidTokenException(response.message);
            }
            return response;
        } catch (HttpClientErrorException e) {
            LOGGER.debug("Could not validate jws {} because of an http error {}", body, e.getResponseBodyAsString(), e);
            throw new InvalidTokenException(e.getResponseBodyAsString());
        }
    }
}
