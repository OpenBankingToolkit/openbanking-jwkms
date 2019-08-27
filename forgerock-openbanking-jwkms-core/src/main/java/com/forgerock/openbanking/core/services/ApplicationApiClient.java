/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.services;

import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.ApplicationIdentity;
import com.forgerock.openbanking.core.model.CertificateAuthority;
import com.nimbusds.jose.jwk.JWK;

public interface ApplicationApiClient {

    String transportKeysJwkUri(String appId);

    Application transportKeysRotate(String appId);

    Application transportKeysReset(String appId);

    String signingEncryptionKeysJwkUri(String appId);

    Application signingEncryptionKeysRotate(String appId);

    Application signingEncryptionKeysReset(String appId);

    Application getApplication(String applicationId);

    Application createApplication(Application applicationRequest);

    CertificateAuthority createCA(CertificateAuthority certificateAuthority);

    ApplicationIdentity authenticate(JWK jwk);

    void deleteApplication(String applicationId);
}
