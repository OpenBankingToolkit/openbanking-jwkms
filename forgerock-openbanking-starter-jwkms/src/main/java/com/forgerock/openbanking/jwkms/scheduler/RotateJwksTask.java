/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.scheduler;

import com.forgerock.openbanking.core.model.jwkms.Application;
import com.forgerock.openbanking.core.model.jwkms.JwkMsKey;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static com.forgerock.openbanking.core.openbanking.OpenBankingConstants.BOOKED_TIME_DATE_FORMAT;

@Component
/**
 * Rotate keys for all the application we managed
 */
public class RotateJwksTask {

    private final static Logger LOGGER = LoggerFactory.getLogger(RotateJwksTask.class);
    private final static DateTimeFormatter format = DateTimeFormat.forPattern(BOOKED_TIME_DATE_FORMAT);

    @Autowired
    private JwkMsConfigurationProperties jwkMsConfigurationProperties;
    @Autowired
    private ApplicationService applicationService;
    @Autowired
    private ApplicationsRepository applicationsRepository;

    /*@Scheduled(cron = "${jwkms.rotationScheduler}")
    @SchedulerLock(name = "rotateKeys")
    public void rotateKeys() {
        LOGGER.info("We are going to rotate keys. The time is now {}. Rotation configuration '{}'",
                format.print(DateTime.now()), jwkMsConfigurationProperties.getRotationScheduler());

        for (Application application: applicationsRepository.findAll()) {
            LOGGER.debug("Check if the application requires to have its keys rotated: " + application);
            LOGGER.debug("Current transport key next rotation time '{}'", format.print(application.getTransportKeysNextRotation()));
            if (application.getTransportKeysNextRotation().isBeforeNow()) {
                applicationService.rotateTransportKeys(application);
            } else {
                LOGGER.debug("Transport keys don't need to be rotated now. Next rotationScheduler is {}", application.getTransportKeysNextRotation());
            }

            LOGGER.debug("Current sign and enc key next rotation time '{}'", format.print(application.getSigningAndEncryptionKeysNextRotation()));
            if (application.getSigningAndEncryptionKeysNextRotation().isBeforeNow()) {
                applicationService.rotateKeys(application);
            } else {
                LOGGER.debug("Signing and encryption keys don't need to be rotated now. Next rotationScheduler is {}", application.getSigningAndEncryptionKeysNextRotation());
            }
        }
    }*/
}
