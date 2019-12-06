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
package com.forgerock.openbanking.jwkms.upgrade;

import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.ForgeRockApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import com.forgerock.openbanking.upgrade.exceptions.UpgradeException;
import com.forgerock.openbanking.upgrade.model.UpgradeMeta;
import com.forgerock.openbanking.upgrade.model.UpgradeStep;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@UpgradeMeta(version = "3.1.2")
public class UpgradeStep_3_1_2 implements UpgradeStep {

    private static final Logger LOGGER = LoggerFactory.getLogger(UpgradeStep.class);

    @Autowired
    private ApplicationsRepository applicationsRepository;
    @Autowired
    private ApplicationService applicationService;
    @Autowired
    private ForgeRockApplicationsRepository forgeRockApplicationsRepository;

    public boolean upgrade() throws UpgradeException {
        LOGGER.debug("Start upgrading to version 3.1.2");
        forgeRockApplicationsRepository.deleteAll();

        List<Application> apps = applicationsRepository.findAll();
        for (Application app: apps) {
            applicationService.resetKeys(app);
            applicationService.resetTransportKeys(app);
        }
        return true;
    }
}
