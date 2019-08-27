/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.serialiser.nimbus;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.nimbusds.jose.JWEAlgorithm;

import java.io.IOException;

public class JweAlgorithmSerializer extends StdSerializer<JWEAlgorithm> {

    public JweAlgorithmSerializer() {
        this(null);
    }

    public JweAlgorithmSerializer(Class<JWEAlgorithm> t) {
        super(t);
    }

    @Override
    public void serialize(JWEAlgorithm jweAlgorithm, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
            throws IOException {
        jsonGenerator.writeObject(jweAlgorithm.getName());
    }
}
