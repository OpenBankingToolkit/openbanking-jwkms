/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.x509;

import com.forgerock.openbanking.core.auth.UserContext;
import com.forgerock.openbanking.core.auth.x509.ForgeRockAppMATLService;
import com.forgerock.openbanking.core.configuration.auth.MATLSConfigurationProperties;
import com.forgerock.openbanking.core.model.jwkms.ApplicationIdentity;
import com.forgerock.openbanking.core.services.directory.DirectoryService;
import com.forgerock.openbanking.core.services.keystore.KeyStoreService;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

@Service
public class JwkMsMatlsService extends ForgeRockAppMATLService {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwkMsMatlsService.class);

    @Autowired
    public JwkMsMatlsService(
            @Value("${certificates.selfsigned.forgerock.root}") Resource forgerockSelfSignedRootCertificatePem,
            @Value("${gateway.client-jwk-header}") String clientJwkHeader,
            DirectoryService directoryService,
            KeyStoreService keyStoreService,
            MATLSConfigurationProperties matlsConfigurationProperties,
            ApplicationService applicationStoreService
    ){
        super(forgerockSelfSignedRootCertificatePem,
                clientJwkHeader,
                directoryService,
                keyStoreService,
                matlsConfigurationProperties);
        this.applicationService = applicationStoreService;
    }


    private ApplicationService applicationService;

    @Override
    protected UserContext getUserDetails(JWK jwk, X509Certificate[] certificatesChain) {
        ApplicationIdentity applicationIdentity = applicationService.authenticate(jwk);
        return UserContext.create(applicationIdentity.getId(), new ArrayList<>(applicationIdentity.getRoles()), UserContext.UserType.JWKMS_APPLICATION);
    }
}
