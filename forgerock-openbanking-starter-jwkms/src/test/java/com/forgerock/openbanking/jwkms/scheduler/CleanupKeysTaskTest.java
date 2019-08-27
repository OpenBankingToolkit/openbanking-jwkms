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