/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.List;

/**
 * A place holder of the AM configuration.
 */
@Service
public class AMOpenBankingConfiguration implements ApplicationConfiguration {
    @Value("${am.oidc.issuerid}")
    public String issuerId;
    @Value("${am.oidc.jwksuri}")
    public String jwksUri;
    @Value("${am.oidc.endpoint.registration}")
    public String registrationEndpoint;
    @Value("${am.cookie.name}")
    public String cookieName;
    @Value("${am.endpoint.userprofile}")
    public String endpointUserProfile;
    @Value("${am.userprofile.id}")
    public String userProfileId;
    @Value("${am.endpoint.login}")
    public String loginPage;
    @Value("${am.endpoint.logout}")
    public String logoutPage;
    @Value("${am.endpoint.users}")
    public String users;
    @Value("${am.endpoint.registration}")
    public String registration;
    @Value("${am.internal.endpoint.authentication}")
    public String authentication;
    @Value("${am.internal.endpoint.oidc-client}")
    public String oidcClient;
    @Value("${am.internal.credential.amadmin}")
    public String amadminPassword;
    @Value("${am.oidc.audiences}")
    public List<String> audiences;

    private JWKSet openamJwkSet = null;


    @Override
    public String getIssuerID() {
        return issuerId;
    }

    /**
     * Get the AM JWKs.
     *
     * @return
     */
    public synchronized JWKSet getJwkSet() {
        if (openamJwkSet == null) {
            try {
                openamJwkSet = JWKSet.load(new URL(jwksUri));
            } catch (IOException e) {
                throw new RuntimeException("Can't connect to AM", e);
            } catch (ParseException e) {
                throw new RuntimeException("Can't parse AM Jwks", e);
            }
        }
        return openamJwkSet;
    }

    /**
     * Get the JWK needed for encrypting JWT to AM
     *
     * @return the JWK for encrypting to AM
     */
    public RSAKey getAMJwkForEncryption() {
        for (JWK jwk : getJwkSet().getKeys()) {
            if (jwk.getKeyUse() == KeyUse.ENCRYPTION
                    && jwk instanceof RSAKey) {
                return (RSAKey) jwk;
            }
        }
        return null;
    }
}
