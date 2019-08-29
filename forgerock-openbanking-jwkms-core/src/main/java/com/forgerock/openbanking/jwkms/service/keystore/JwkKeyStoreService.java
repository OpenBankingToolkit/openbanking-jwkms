/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.service.keystore;

import com.forgerock.openbanking.ssl.services.keystore.KeyStoreFileService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.security.KeyStoreException;

@Service
/**
 * Representation of a keystore
 */
public class JwkKeyStoreService extends KeyStoreFileService {

    JwkKeyStoreService(@Value("${server.ssl.jwk-key-store-password}") String keyStorePassword,
                       @Value("${server.ssl.jwk-key-store}") Resource keyStoreResource){
        this.keyStorePassword = keyStorePassword;
        this.keyStoreResource = keyStoreResource;
    }

    private static final String JAVA_KEYSTORE = "PKCS12";

    private String keyStorePassword;
    private Resource keyStoreResource;

    @Override
    public Resource getKeyStoreResource() {
        return keyStoreResource;
    }

    @Override
    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    @Override
    public KeyStore getKeyStoreInstance() throws KeyStoreException {
        return KeyStore.getInstance(JAVA_KEYSTORE, new BouncyCastleProvider());
    }
}
