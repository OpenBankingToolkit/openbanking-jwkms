/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.serialiser.nimbus;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.text.ParseException;

public class JWKSetDeserializer extends StdDeserializer<JWKSet> {
    private static final Logger LOGGER = LoggerFactory.getLogger(JWKSetDeserializer.class);

    public JWKSetDeserializer() {
        this(null);
    }

    public JWKSetDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public JWKSet deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
            throws IOException {
        String jwkSetSerialised = jsonParser.readValueAsTree().toString();
        try {
            return JWKSet.parse(jwkSetSerialised);
        } catch (ParseException e) {
            LOGGER.error("can't deserialize JWK set {}", jwkSetSerialised, e);
            return null;
        }
    }
}
