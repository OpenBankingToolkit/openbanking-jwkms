/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.services;

import com.forgerock.openbanking.ssl.model.ForgeRockApplicationResponse;
import com.forgerock.openbanking.ssl.services.ForgeRockApplicationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

/**
 * Access the Jwk MS services
 */
public class ForgeRockApplicationServiceImpl implements ForgeRockApplicationService {
    private static final Logger LOGGER = LoggerFactory.getLogger(ForgeRockApplicationServiceImpl.class);

    @Value("${jwkms.root}")
    private String jwkmsRoot;

    /**
     * Get application
     */
    @Override
    public ForgeRockApplicationResponse getCurrentApplication(RestTemplate restTemplate) {
        ParameterizedTypeReference<ForgeRockApplicationResponse> ptr = new ParameterizedTypeReference<ForgeRockApplicationResponse>() {};
        ResponseEntity<ForgeRockApplicationResponse> entity = restTemplate.exchange(jwkmsRoot + "api/application/current",
                HttpMethod.GET, null, ptr);

        return entity.getBody();
    }

}
