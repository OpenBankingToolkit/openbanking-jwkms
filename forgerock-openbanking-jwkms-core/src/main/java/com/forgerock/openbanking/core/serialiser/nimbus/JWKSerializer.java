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
import com.nimbusds.jose.jwk.JWK;

import java.io.IOException;

public class JWKSerializer extends StdSerializer<JWK> {

    public JWKSerializer() {
        this(null);
    }

    public JWKSerializer(Class<JWK> t) {
        super(t);
    }

    @Override
    public void serialize(JWK jwk, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
            throws IOException {
        jsonGenerator.writeObject(jwk.toJSONObject());
    }
}
