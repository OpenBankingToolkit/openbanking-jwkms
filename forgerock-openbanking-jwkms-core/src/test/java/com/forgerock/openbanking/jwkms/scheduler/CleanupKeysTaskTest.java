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
package com.forgerock.openbanking.jwkms.scheduler;

import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.JwkMsKey;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import org.assertj.core.util.Maps;
import org.joda.time.DateTime;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class CleanupKeysTaskTest {

    @Mock
    private JwkMsConfigurationProperties jwkMsConfigurationProperties;
    @Mock
    private ApplicationsRepository applicationsRepository;
    @InjectMocks
    private CleanupKeysTask cleanupKeysTask;

    @Test
    public void shouldNotSaveIfSigningKeysUnchanged() {
        // Given
        Application application = new Application();
        JwkMsKey key = new JwkMsKey();
        key.setValidityWindowStop(DateTime.now());
        application.setKeys(Maps.newHashMap("signing", key));
        given(applicationsRepository.streamAll()).willReturn(Stream.of(application));

        // When
        cleanupKeysTask.rotateKeys();

        // Then
        verify(applicationsRepository, never()).save(application);
    }

    @Test
    public void shouldNotSaveIfTransportKeysUnchanged() {
        // Given
        Application application = new Application();
        JwkMsKey key = new JwkMsKey();
        key.setValidityWindowStop(DateTime.now());
        application.setTransportKeys(Maps.newHashMap("transport", key));
        given(applicationsRepository.streamAll()).willReturn(Stream.of(application));

        // When
        cleanupKeysTask.rotateKeys();

        // Then
        verify(applicationsRepository, never()).save(application);
    }

    @Test
    public void shouldRemoveSigningKeyWhenExpiredAndWeekOld() {
        // Given
        Application application = new Application();
        JwkMsKey key = new JwkMsKey();
        key.setValidityWindowStop(DateTime.now().minusWeeks(2));
        application.setKeys(Maps.newHashMap("signing", key));
        given(applicationsRepository.streamAll()).willReturn(Stream.of(application));

        // When
        cleanupKeysTask.rotateKeys();

        // Then
        verify(applicationsRepository).save(application);
        assertThat(application.getKeys()).hasSize(0);
    }

    @Test
    public void shouldRemoveTransportKeyWhenExpiredAndWeekOld() {
        // Given
        Application application = new Application();
        JwkMsKey key = new JwkMsKey();
        key.setValidityWindowStop(DateTime.now().minusWeeks(2));
        application.setTransportKeys(Maps.newHashMap("transport", key));
        given(applicationsRepository.streamAll()).willReturn(Stream.of(application));

        // When
        cleanupKeysTask.rotateKeys();

        // Then
        verify(applicationsRepository).save(application);
        assertThat(application.getTransportKeys()).hasSize(0);
    }

    @Test
    public void shouldNotRemoveSigningKeyWhenExpiredAndWeekOld() {
        // Given
        Application application = new Application();
        JwkMsKey key = new JwkMsKey();
        key.setValidityWindowStop(DateTime.now());
        application.setKeys(Maps.newHashMap("signing", key));
        given(applicationsRepository.streamAll()).willReturn(Stream.of(application));

        // When
        cleanupKeysTask.rotateKeys();

        // Then
        assertThat(application.getKeys()).hasSize(1);
    }

    @Test
    public void shouldNotRemoveTransportKeyWhenExpiredAndWeekOld() {
        // Given
        Application application = new Application();
        JwkMsKey key = new JwkMsKey();
        key.setValidityWindowStop(DateTime.now());
        application.setTransportKeys(Maps.newHashMap("transport", key));
        given(applicationsRepository.streamAll()).willReturn(Stream.of(application));

        // When
        cleanupKeysTask.rotateKeys();

        // Then
        assertThat(application.getTransportKeys()).hasSize(1);
    }
}