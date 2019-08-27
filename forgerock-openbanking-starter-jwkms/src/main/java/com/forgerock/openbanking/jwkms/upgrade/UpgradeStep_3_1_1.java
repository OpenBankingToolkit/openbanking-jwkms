/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.upgrade;

import com.forgerock.openbanking.core.model.jwkms.Application;
import com.forgerock.openbanking.core.upgrade.UpgradeException;
import com.forgerock.openbanking.core.upgrade.UpgradeMeta;
import com.forgerock.openbanking.core.upgrade.UpgradeStep;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.ForgeRockApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@UpgradeMeta(version = "3.1.1")
public class UpgradeStep_3_1_1 implements UpgradeStep {

    private static final Logger LOGGER = LoggerFactory.getLogger(UpgradeStep.class);

    @Autowired
    private ApplicationsRepository applicationsRepository;
    @Autowired
    private ApplicationService applicationService;
    @Autowired
    private ForgeRockApplicationsRepository forgeRockApplicationsRepository;

    public boolean upgrade() throws UpgradeException {
        LOGGER.debug("Start upgrading to version 3.1.1");
        forgeRockApplicationsRepository.deleteAll();

        List<Application> apps = applicationsRepository.findAll();
        for (Application app: apps) {
            applicationService.resetKeys(app);
            applicationService.resetTransportKeys(app);
        }
        return true;
    }
}
