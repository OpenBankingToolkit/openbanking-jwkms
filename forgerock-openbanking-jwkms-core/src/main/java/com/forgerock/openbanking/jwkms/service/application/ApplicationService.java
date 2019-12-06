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
package com.forgerock.openbanking.jwkms.service.application;

import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.model.ApplicationIdentity;
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
