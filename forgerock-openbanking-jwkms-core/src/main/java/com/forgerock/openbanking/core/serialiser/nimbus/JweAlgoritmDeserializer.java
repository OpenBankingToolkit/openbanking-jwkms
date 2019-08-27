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
import com.nimbusds.jose.JWEAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class JweAlgoritmDeserializer extends StdDeserializer<JWEAlgorithm> {
    private static final Logger LOGGER = LoggerFactory.getLogger(JweAlgoritmDeserializer.class);

    public JweAlgoritmDeserializer() {
        this(null);
    }

    public JweAlgoritmDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public JWEAlgorithm deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
            throws IOException {
        return JWEAlgorithm.parse(jsonParser.getText());
    }
}
