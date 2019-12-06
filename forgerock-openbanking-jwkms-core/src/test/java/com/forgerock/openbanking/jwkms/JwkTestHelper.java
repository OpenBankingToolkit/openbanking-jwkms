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
package com.forgerock.openbanking.jwkms;

import com.forgerock.openbanking.core.model.JwkMsKey;
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
