/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.model;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.forgerock.openbanking.core.serialiser.nimbus.JWKDeserializer;
import com.forgerock.openbanking.core.serialiser.nimbus.JWKSerializer;
import com.nimbusds.jose.jwk.JWK;

public class ForgeRockApplicationResponse {

    private String applicationId;

    @JsonDeserialize(using = JWKDeserializer.class)
    @JsonSerialize(using = JWKSerializer.class)
    private JWK transportKey;

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public JWK getTransportKey() {
        return transportKey;
    }

    public void setTransportKey(JWK transportKey) {
        this.transportKey = transportKey;
    }
}
