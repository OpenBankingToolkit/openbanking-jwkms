/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
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