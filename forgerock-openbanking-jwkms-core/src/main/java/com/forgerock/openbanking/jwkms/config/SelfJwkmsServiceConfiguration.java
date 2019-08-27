/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.config;

import com.forgerock.openbanking.auth.services.ForgeRockApplicationService;
import com.forgerock.openbanking.jwkms.service.JwkmsServiceConfiguration;
import com.forgerock.openbanking.jwkms.service.jwkms.ForgeRockApplicationServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class SelfJwkmsServiceConfiguration extends JwkmsServiceConfiguration {

    @Bean
    @Primary
    public ForgeRockApplicationService forgeRockApplicationService() {
        return new ForgeRockApplicationServiceImpl();
    }
}
