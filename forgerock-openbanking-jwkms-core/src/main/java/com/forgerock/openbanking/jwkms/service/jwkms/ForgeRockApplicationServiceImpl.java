/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.service.jwkms;

import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.auth.model.ForgeRockApplicationResponse;
import com.forgerock.openbanking.auth.services.ForgeRockApplicationService;
import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.ForgeRockApplication;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.ForgeRockApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import com.forgerock.openbanking.jwkms.service.jwkstore.JwkStoreService;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

/**
 * Access the Jwk MS services
 */
public class ForgeRockApplicationServiceImpl implements ForgeRockApplicationService {
    private static final Logger LOGGER = LoggerFactory.getLogger(ForgeRockApplicationServiceImpl.class);

    @Autowired
    private JwkMsConfigurationProperties jwkMsConfigurationProperties;
    @Autowired
    private ApplicationService applicationService;

    @Autowired
    private ApplicationsRepository applicationsRepository;
    @Autowired
    private ForgeRockApplicationsRepository forgeRockApplicationsRepository;
    @Autowired
    private JwkStoreService jwkStoreService;
    /**
     * Get application
     */
    @Override
    public ForgeRockApplicationResponse getCurrentApplication(RestTemplate restTemplate) {
        Optional<ForgeRockApplication> isApp = forgeRockApplicationsRepository.findById(jwkMsConfigurationProperties.getJwkMsId());
        Application application;
        if (!isApp.isPresent()) {
            application = createApplication();
            ForgeRockApplication forgeRockApplication = new ForgeRockApplication();
            forgeRockApplication.setApplicationId(application.getIssuerId());
            forgeRockApplication.setName(jwkMsConfigurationProperties.getJwkMsId());
            forgeRockApplicationsRepository.save(forgeRockApplication);

        } else {
            application = applicationsRepository.findById(isApp.get().getApplicationId()).get();
        }

        ForgeRockApplicationResponse forgeRockApplicationResponse = new ForgeRockApplicationResponse();
        forgeRockApplicationResponse.setApplicationId(application.getIssuerId());
        forgeRockApplicationResponse.setTransportKey(application.getCurrentTransportKey().getJwk());

        return forgeRockApplicationResponse;
    }

    private Application createApplication() {
        Application application = new Application();

        application.setDefaultSigningAlgorithm(jwkMsConfigurationProperties.getJWSAlgorithm());
        application.setDefaultEncryptionAlgorithm(jwkMsConfigurationProperties.getJWEAlgorithm());
        application.setDefaultEncryptionMethod(jwkMsConfigurationProperties.getEncryptionMethod());
        application.setDefaultTransportSigningAlgorithm(jwkMsConfigurationProperties.getTransportJWSAlgorithm());
        application.setExpirationWindow(Duration.millis(jwkMsConfigurationProperties.getExpirationWindowInMillis()));
        application.setCertificateConfiguration(new CertificateConfiguration());
        application.getCertificateConfiguration().setCn(jwkMsConfigurationProperties.getJwkMsId());
        application.getCertificateConfiguration().setOu(jwkMsConfigurationProperties.getCertificate().getOu());
        application.getCertificateConfiguration().setO(jwkMsConfigurationProperties.getCertificate().getO());
        application.getCertificateConfiguration().setL(jwkMsConfigurationProperties.getCertificate().getL());
        application.getCertificateConfiguration().setSt(jwkMsConfigurationProperties.getCertificate().getSt());
        application.getCertificateConfiguration().setC(jwkMsConfigurationProperties.getCertificate().getC());

        applicationService.resetKeys(application);
        applicationService.resetTransportKeys(application);
        return applicationsRepository.save(application);
    }
}
