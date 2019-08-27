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
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.text.ParseException;

public class JWKDeserializer extends StdDeserializer<JWK> {
    private static final Logger LOGGER = LoggerFactory.getLogger(JWKDeserializer.class);

    public JWKDeserializer() {
        this(null);
    }

    public JWKDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public JWK deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
            throws IOException {
        String jwkSerialised = jsonParser.readValueAsTree().toString();
        try {
            return JWK.parse(jwkSerialised);
        } catch (ParseException e) {
            LOGGER.error("can't deserialize JWK {}", jwkSerialised, e);
            return null;
        }
    }
}
