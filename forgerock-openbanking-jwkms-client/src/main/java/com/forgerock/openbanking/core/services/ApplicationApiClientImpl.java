/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.services;

import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.ApplicationIdentity;
import com.forgerock.openbanking.core.model.CertificateAuthority;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@Service
/**
 * Access the Jwk MS services
 */
public class ApplicationApiClientImpl implements ApplicationApiClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(ApplicationApiClientImpl.class);

    @Value("${jwkms.root}")
    private String jwkmsRoot;
    @Autowired
    private RestTemplate restTemplate;

    /**
     * Get the public JWK uri of an application for the transport keys
     * @param appId the application ID
     * @return the public JWKs
     */
    @Override
    public String transportKeysJwkUri(String appId)  {
        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/transport/jwk_uri" );
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<String> entity = restTemplate.exchange(uri, HttpMethod.GET, null, ptr);
        return entity.getBody();
    }

    @Override
    public Application transportKeysRotate(String appId)  {
        ParameterizedTypeReference<Application> ptr = new ParameterizedTypeReference<Application>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/transport/rotate/");
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<Application> entity = restTemplate.exchange(uri, HttpMethod.PUT, null, ptr);
        return entity.getBody();
    }

    @Override
    public Application transportKeysReset(String appId)  {
        ParameterizedTypeReference<Application> ptr = new ParameterizedTypeReference<Application>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/transport/reset/" );
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<Application> entity = restTemplate.exchange(uri, HttpMethod.PUT, null, ptr);
        return entity.getBody();
    }

    /**
     * Get the public JWK uri of an application
     * @param appId the application ID
     * @return the public JWKs
     */
    @Override
    public String signingEncryptionKeysJwkUri(String appId)  {
        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/jwk_uri");
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<String> entity = restTemplate.exchange(uri, HttpMethod.GET, null, ptr);
        return entity.getBody();
    }

    @Override
    public Application signingEncryptionKeysRotate(String appId)  {
        ParameterizedTypeReference<Application> ptr = new ParameterizedTypeReference<Application>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/rotate/");
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<Application> entity = restTemplate.exchange(uri, HttpMethod.PUT, null, ptr);
        return entity.getBody();
    }

    @Override
    public Application signingEncryptionKeysReset(String appId)  {
        ParameterizedTypeReference<Application> ptr = new ParameterizedTypeReference<Application>() {};
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(jwkmsRoot + "api/application/" + appId + "/reset/" );
        URI uri = builder.build().encode().toUri();

        LOGGER.debug("Get the jwk_uri for {}. Call jwkms with {}", appId, uri);
        ResponseEntity<Application> entity = restTemplate.exchange(uri, HttpMethod.PUT, null, ptr);
        return entity.getBody();
    }


    /**
     * Get application
     */
    @Override
    public Application getApplication(String applicationId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map= new LinkedMultiValueMap<String, String>();

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<MultiValueMap<String, String>>(map, headers);

        ParameterizedTypeReference<Application> ptr = new ParameterizedTypeReference<Application>() {
        };
        ResponseEntity<Application> entity = restTemplate.exchange(jwkmsRoot + "api/application/" + applicationId,
                HttpMethod.GET, null, ptr);

        return entity.getBody();
    }

    /**
     * Get application
     */
    @Override
    public Application createApplication(Application applicationRequest) {
        HttpEntity<Application> request = new HttpEntity<>(applicationRequest, new HttpHeaders());
        return restTemplate.exchange(jwkmsRoot + "api/application/", HttpMethod.POST, request, Application.class).getBody();
    }

    /**
     * Get application
     */
    @Override
    public CertificateAuthority createCA(CertificateAuthority certificateAuthority) {
        HttpEntity<CertificateAuthority> request = new HttpEntity<>(certificateAuthority, new HttpHeaders());
        return restTemplate.exchange(jwkmsRoot + "api/ca/", HttpMethod.POST, request, CertificateAuthority.class).getBody();
    }

    @Override
    public ApplicationIdentity authenticate(JWK jwk) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<ApplicationIdentity> ptr = new ParameterizedTypeReference<ApplicationIdentity>() {};
        HttpEntity<String> request = new HttpEntity<>(jwk.toJSONObject().toJSONString(), headers);

        ResponseEntity<ApplicationIdentity> entity = restTemplate.exchange(jwkmsRoot + "api/application/authenticate",
                HttpMethod.POST, request, ptr);

        return entity.getBody();
    }

    @Override
    public void deleteApplication(String applicationId) {
        restTemplate.exchange(jwkmsRoot + "api/application/" + applicationId, HttpMethod.DELETE,
                null, Void.class).getBody();
    }

}