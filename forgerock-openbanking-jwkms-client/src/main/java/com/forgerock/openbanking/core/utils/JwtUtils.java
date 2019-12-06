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
package com.forgerock.openbanking.core.utils;

import com.nimbusds.jose.JWSHeader;

import java.io.UnsupportedEncodingException;
import java.text.ParseException;

public class JwtUtils {

    public static byte[] getSingingInputNonEncodedPayload(JWSHeader header, String payload) throws UnsupportedEncodingException, ParseException {
        byte[] signingInput;
        byte[] payloadBytes = payload.getBytes("UTF-8");
        byte[] headerBytes = (header.toBase64URL().toString() + '.').getBytes("UTF-8");
        signingInput = new byte[headerBytes.length + payloadBytes.length];
        System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
        System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length, payloadBytes.length);
        return signingInput;
    }
}