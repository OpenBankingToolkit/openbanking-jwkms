/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.scheduler;

import com.forgerock.openbanking.core.model.jwkms.Application;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import net.javacrumbs.shedlock.core.SchedulerLock;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.stream.Stream;

import static com.forgerock.openbanking.core.openbanking.OpenBankingConstants.BOOKED_TIME_DATE_FORMAT;

@Component
/**
 * Rotate keys for all the application we managed
 */
public class CleanupKeysTask {

    private final static Logger LOGGER = LoggerFactory.getLogger(CleanupKeysTask.class);
    private final static DateTimeFormatter format = DateTimeFormat.forPattern(BOOKED_TIME_DATE_FORMAT);

    @Autowired
    private JwkMsConfigurationProperties jwkMsConfigurationProperties;
    @Autowired
    private ApplicationsRepository applicationsRepository;


    @Scheduled(cron = "${jwkms.keysCleanup}")
    @SchedulerLock(name = "keysCleanup")
    public void rotateKeys() {
        LOGGER.info("We are going to rotate keys. The time is now {}. Rotation configuration '{}'",
                format.print(DateTime.now()), jwkMsConfigurationProperties.getRotationScheduler());
        try (Stream<Application> apps = applicationsRepository.streamAll()) {
            apps.forEach(app -> {
                LOGGER.debug("Check if the application requires to have some keys removed: " + app);
                boolean keysChanged = app.getKeys().values().removeIf(k -> k.getValidityWindowStop().isBefore(DateTime.now().minusWeeks(1)));
                boolean transportKeysChanged = app.getTransportKeys().values().removeIf(k -> k.getValidityWindowStop().isBefore(DateTime.now().minusWeeks(1)));
                if (keysChanged || transportKeysChanged) applicationsRepository.save(app);
            });
        }
    }
}
