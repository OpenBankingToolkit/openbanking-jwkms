/**
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
package com.forgerock.openbanking.jwkms.scheduler;

import com.forgerock.openbanking.core.model.Application;
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

@Component
/**
 * Rotate keys for all the application we managed
 */
public class CleanupKeysTask {

    private final static Logger LOGGER = LoggerFactory.getLogger(CleanupKeysTask.class);
    private final static DateTimeFormatter format = DateTimeFormat.forPattern( "yyyy-MM-dd'T'HH:mm:ss");

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
