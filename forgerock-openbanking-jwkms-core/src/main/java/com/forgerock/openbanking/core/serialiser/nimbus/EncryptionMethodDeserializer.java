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
import com.nimbusds.jose.EncryptionMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class EncryptionMethodDeserializer extends StdDeserializer<EncryptionMethod> {
    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionMethodDeserializer.class);

    public EncryptionMethodDeserializer() {
        this(null);
    }

    public EncryptionMethodDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public EncryptionMethod deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
            throws IOException {
        return EncryptionMethod.parse(jsonParser.getText());
    }
}
