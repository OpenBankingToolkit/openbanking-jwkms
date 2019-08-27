/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.openbanking.core.configuration.applications.AMOpenBankingConfiguration;
import com.forgerock.openbanking.core.exception.InvalidTokenException;
import com.forgerock.openbanking.core.model.csr.CSRGenerationResponse;
import com.forgerock.openbanking.core.model.csr.CSRImportPemsRequest;
import com.forgerock.openbanking.core.model.SigningRequest;
import com.forgerock.openbanking.core.rest.CreateDetachedJwtResponse;
import com.forgerock.openbanking.core.rest.ValidJwtResponse;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.Resource;
import java.net.URI;
import java.text.ParseException;

@Service
public class CryptoApiClientImpl implements CryptoApiClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoApiClientImpl.class);
    
    @Value("${jwkms.root}")
    private String jwkmsRoot;

    @Resource(name = "forExternal")
    private RestTemplate restTemplate;

    @Resource(name = "forExternalForgeRockApplication")
    private RestTemplate restTemplateForForgeRockApp;

    @Autowired
    private AMOpenBankingConfiguration amOpenBankingConfiguration;
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public JWK getKey(String appId, String keyId) throws ParseException {
        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/key/" + keyId);
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<String> entity = restTemplateForForgeRockApp.exchange(uri, HttpMethod.PUT, null, ptr);
        return JWK.parse(entity.getBody());
    }

    public String getPublicCert(String appId, String keyId) {
        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/key/" + keyId + "/certificate/public/");
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<String> entity = restTemplateForForgeRockApp.exchange(uri, HttpMethod.PUT, null, ptr);
        return entity.getBody();
    }

    public String getPrivateCert(String appId, String keyId) {
        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/key/" + keyId + "/certificate/private/");
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<String> entity = restTemplateForForgeRockApp.exchange(uri, HttpMethod.PUT, null, ptr);
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
    public String signClaims(String issuerId, JWTClaimsSet jwtClaimsSet) {
        return signClaims(restTemplate, null, issuerId, jwtClaimsSet);
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
        return signClaims(restTemplate, signingRequest, issuerId, jwtClaimsSet.toString(), "signClaims");
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

    private String signClaims(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, String payload, String path)  {
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
    public void validateJws(String serializedJws, String expectedIssuerId) throws InvalidTokenException {
        validateJwsWithExpectedAudience(serializedJws, null, expectedIssuerId);
    }

    /**
     * Validate a JWS
     * @param serializedJws the jws serialized
     * @param expectedIssuerId the expected issuer ID
     * @throws InvalidTokenException the JWS is invalid
     */
    @Override
    public void validateJwsWithExpectedAudience(String serializedJws, String expectedAudienceId, String expectedIssuerId) throws InvalidTokenException {
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
    }

    /**
     * Validate a JWS
     * @param serializedJws the jws serialized
     * @param expectedIssuerId the expected issuer ID
     * @param jwkUri the issuer jwk URI
     * @throws InvalidTokenException the JWS is invalid
     */
    @Override
    public void validateJws(String serializedJws, String expectedIssuerId, String jwkUri) throws InvalidTokenException {
        validateJws(serializedJws, null, expectedIssuerId, jwkUri);
    }


    @Override
    public void validateJwsWithJWK(String serializedJws, String expectedIssuerId, String jwk) throws InvalidTokenException {
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
    public void validateJws(String serializedJws, String expectedAudienceId, String expectedIssuerId, String jwkUri)
            throws InvalidTokenException {
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
        } catch (HttpClientErrorException e) {
            LOGGER.debug("Could not validate jws {} because of an http error {}", serializedJws, e.getResponseBodyAsString(), e);
            throw new InvalidTokenException(e.getResponseBodyAsString());
        }
    }

    @Override
    public void validateDetachedJWS(String jwsDetachedSignature, Object body, String expectedAudienceId, String expectedIssuerId, String jwkUri)
            throws InvalidTokenException {
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
            ValidJwtResponse response = restTemplate.exchange(jwkmsRoot + "api/crypto/validateDetachedJWSWithJwkUri", HttpMethod.POST, request,
                    ValidJwtResponse.class).getBody();
            if (!response.isValid) {
                throw new InvalidTokenException(response.message);
            }
        } catch (HttpClientErrorException e) {
            LOGGER.debug("Could not validate jws {} because of an http error {}", body, e.getResponseBodyAsString(), e);
            throw new InvalidTokenException(e.getResponseBodyAsString());
        }
    }

    @Override
    public void validateDetachedJWSWithJWK(String jwsDetachedSignature, Object body, String expectedAudienceId, String expectedIssuerId, JWK jwk)
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
            ValidJwtResponse response = restTemplate.exchange(jwkmsRoot + "api/crypto/validateDetachedJWSWithJWK", HttpMethod.POST, request,
                    ValidJwtResponse.class).getBody();
            if (!response.isValid) {
                throw new InvalidTokenException(response.message);
            }
        } catch (HttpClientErrorException e) {
            LOGGER.debug("Could not validate jws {} because of an http error {}", body, e.getResponseBodyAsString(), e);
            throw new InvalidTokenException(e.getResponseBodyAsString());
        }
    }

    /**
     * Verify a stateless access token
     * @param accessTokenBearer an access token bearer or the JWT directly
     * @return the JWS
     * @throws ParseException can't parse the access token JWT, must not be a stateless JWT
     * @throws InvalidTokenException the access token is invalid
     */
    @Override
    public SignedJWT verifyAccessToken(String accessTokenBearer)
            throws ParseException, InvalidTokenException {
        accessTokenBearer = accessTokenBearer.replaceFirst("^Bearer ", "");
        SignedJWT signedAccessToken = (SignedJWT) JWTParser.parse(accessTokenBearer);
        validateJws(accessTokenBearer,null, amOpenBankingConfiguration.jwksUri);
        if (!amOpenBankingConfiguration.audiences.contains(signedAccessToken.getJWTClaimsSet().getIssuer())) {
            LOGGER.debug("Invalid audience {}, expecting {}", signedAccessToken.getJWTClaimsSet().getIssuer(), amOpenBankingConfiguration.audiences);
            throw new InvalidTokenException("Invalid audience '" + signedAccessToken.getJWTClaimsSet().getIssuer() + "', expecting '" +
                    amOpenBankingConfiguration.audiences + "'");
        }
        return signedAccessToken;
    }

    /**
     * Generate CSRs
     */
    @Override
    public CSRGenerationResponse generateCSR(String CN, String OU, String O) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map= new LinkedMultiValueMap<String, String>();
        map.add("CN", CN);
        map.add("OU", OU);
        map.add("O", O);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<MultiValueMap<String, String>>(map, headers);

        ResponseEntity<CSRGenerationResponse> response = restTemplate.postForEntity( jwkmsRoot + "api/crypto/generateCSR",
                request , CSRGenerationResponse.class );
        return response.getBody();
    }

    /**
     * Import CSRs
     */
    @Override
    public CSRGenerationResponse importCSRResponse(CSRImportPemsRequest csrImportPemsRequest) {
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<CSRImportPemsRequest> request = new HttpEntity<>(csrImportPemsRequest, headers);
        return restTemplate.postForObject(jwkmsRoot + "api/crypto/importCSRResponse", request,
                CSRGenerationResponse.class);
    }

    /**
     * Export Pem
     */
    @Override
    public String exportAsPem(KeyUse keyUse) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map= new LinkedMultiValueMap<String, String>();
        map.add("keyUse", keyUse.identifier());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<MultiValueMap<String, String>>(map, headers);

        ResponseEntity<String> response = restTemplate.postForEntity( jwkmsRoot + "api/crypto/exportAsPem",
                request , String.class);
        return response.getBody();
    }

}
