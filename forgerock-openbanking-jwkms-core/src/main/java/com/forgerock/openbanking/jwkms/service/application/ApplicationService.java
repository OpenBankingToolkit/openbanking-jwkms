/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.service.application;

import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.ApplicationIdentity;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.ssl.model.csr.CSRGenerationResponse;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;

import java.security.cert.CertificateException;

/**
 * Application keys service. Managed the different applications managed by the JWK MS.
 */
public interface ApplicationService {

    /**
     * Rotate the keys for the corresponding application
     * @param application the application
     */
    void rotateKeys(Application application);

    /**
     * Delete application
     * @param application the application
     */
    void deleteApplication(Application application);

    /**
     * Reset all keys for the corresponding application
     * @param application the application
     */
    void resetKeys(Application application);

    /**
     * Rotate the keys for the corresponding application
     * @param application the application
     */
    void rotateTransportKeys(Application application);


    /**
     * Reset all keys for the corresponding application
     * @param application the application
     */
    void resetTransportKeys(Application application);

    /**
     * Generate a CSR
     * @param application the application
     * @param keyUse keyUse
     */
    CSRGenerationResponse generateCSR(Application application, KeyUse keyUse, CertificateConfiguration certificateConfiguration)
            throws CertificateException;

    /**
     * Import the CSR response
     * @param application the application
     * @param pem the certificate pem returned by the CA_APP
     */
    void importCSRResponse(Application application, String alias, String kid, KeyUse keyUse, String pem)
            throws CertificateException;


    ApplicationIdentity authenticate(JWK jwk);

    Application getApplication(String username);

    Application createApplication(Application applicationRequest);

    Application updateJWKMSApplicationFromForgeRockAppConfig(
            String name,
            JwkMsConfigurationProperties.ForgeRockApplication forgeRockApplicationConfig,
            Application application);
}
