/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.service;

import com.forgerock.openbanking.core.services.*;
import com.forgerock.openbanking.ssl.services.ForgeRockApplicationService;
import org.springframework.context.annotation.Bean;

public class JwkmsServiceConfiguration {

    @Bean
    public CryptoApiClient cryptoApiClient() {
        return new CryptoApiClientImpl();
    }

    @Bean
    public ApplicationApiClient applicationApiClient() { return new ApplicationApiClientImpl(); }

    @Bean
    public ForgeRockApplicationService forgeRockApplicationService() {
        return new ForgeRockApplicationServiceImpl();
    }
}
