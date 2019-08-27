/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.upgrade;

import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.JwkMsKey;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.jwkstore.JwkStoreService;
import com.forgerock.openbanking.upgrade.exceptions.UpgradeException;
import com.forgerock.openbanking.upgrade.model.UpgradeMeta;
import com.forgerock.openbanking.upgrade.model.UpgradeStep;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@UpgradeMeta(version = "2.2.2")
public class UpgradeStep_2_2_2 implements UpgradeStep {

    private static final Logger LOGGER = LoggerFactory.getLogger(UpgradeStep.class);

    @Autowired
    private ApplicationsRepository applicationsRepository;
    @Autowired
    private JwkStoreService jwkStoreService;

    public boolean upgrade() throws UpgradeException {
        LOGGER.debug("Start upgrading to version 2.2.2");
        LOGGER.debug("Loading the private key from the keystore to the DB as a private JWK");
        List<Application> apps = applicationsRepository.findAll();
        for (Application app: apps) {
            LOGGER.debug("Compute app '{}'", app.getIssuerId());
            app.getKeys().values().removeIf(k -> k.getValidityWindowStop() != null);
            for (JwkMsKey key: app.getKeys().values()) {
                computeKey(app, key);
            }

            app.getTransportKeys().values().removeIf(k -> k.getValidityWindowStop() != null);
            for (JwkMsKey key: app.getTransportKeys().values()) {
                computeKey(app, key);
            }
            app.setCurrentTransportKeyHash(app.getCurrentTransportKey().getJwk().getX509CertSHA256Thumbprint().toString());
        }
        applicationsRepository.saveAll(apps);
        return true;
    }

    private void computeKey(Application app, JwkMsKey key) {
        LOGGER.debug("Compute key '{}' with key alias '{}'", key.getKid(), key.getKeystoreAlias());
        JWK privateJWK = jwkStoreService.getPrivateJWK(key);
        if (privateJWK != null) {
            key.setJwk(privateJWK);
        } else {
            LOGGER.debug("Couldn't load the private key from the keystore");
        }
    }
}
