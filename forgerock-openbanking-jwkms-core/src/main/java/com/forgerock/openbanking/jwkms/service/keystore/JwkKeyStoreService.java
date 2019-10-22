/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.service.keystore;

import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreFileService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.security.KeyStoreException;

@Service
/**
 * Representation of a keystore
 */
public class JwkKeyStoreService extends KeyStoreFileService {

    private JwkMsConfigurationProperties jwkMsConfigurationProperties;

    JwkKeyStoreService(JwkMsConfigurationProperties jwkMsConfigurationProperties){
        this.jwkMsConfigurationProperties = jwkMsConfigurationProperties;
    }

    private static final String JAVA_KEYSTORE = "PKCS12";


    @Override
    public Resource getKeyStoreResource() {
        return jwkMsConfigurationProperties.getJwkKeyStore();
    }

    @Override
    public String getKeyStorePassword() {
        return jwkMsConfigurationProperties.getJwkKeyStorePassword();
    }

    @Override
    public KeyStore getKeyStoreInstance() throws KeyStoreException {
        return KeyStore.getInstance(JAVA_KEYSTORE, new BouncyCastleProvider());
    }
}
