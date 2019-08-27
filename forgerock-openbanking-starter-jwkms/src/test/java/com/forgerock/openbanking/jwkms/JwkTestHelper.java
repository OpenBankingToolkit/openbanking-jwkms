/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms;

import com.forgerock.openbanking.core.model.jwkms.JwkMsKey;
import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.nimbusds.jose.jwk.JWK;

import java.io.IOException;
import java.text.ParseException;
import java.util.function.Function;

public class JwkTestHelper {

    public static final Function<JWK, JwkMsKey> jwkToJwkMsKey = jwk -> {
        JwkMsKey key = new JwkMsKey();
        key.setKid(jwk.getKeyID());
        key.setKeyUse(jwk.getKeyUse());
        key.setAlgorithm(jwk.getAlgorithm());
        key.setJwk(jwk);
        return key;
    };

    public static final Function<String, JWK> stringToJWK = str -> {
        try {
            return JWK.parse(str);
        } catch (ParseException e) {
            throw new IllegalArgumentException(e);
        }
    };

    public static final Function<String, String> utf8FileToString = fileName -> {
        try {
            return Resources.toString(Resources.getResource(fileName), Charsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    };
}
