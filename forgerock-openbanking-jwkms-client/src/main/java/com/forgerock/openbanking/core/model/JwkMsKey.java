/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.forgerock.openbanking.serialiser.IsoDateTimeDeserializer;
import com.forgerock.openbanking.serialiser.IsoDateTimeSerializer;
import com.forgerock.openbanking.serialiser.nimbus.JWKDeserializer;
import com.forgerock.openbanking.serialiser.nimbus.JWKSerializer;
import com.forgerock.openbanking.serialiser.nimbus.KeyUseDeserializer;
import com.forgerock.openbanking.serialiser.nimbus.KeyUseSerializer;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.*;
import org.joda.time.DateTime;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.text.ParseException;

/**
 * Representation of a key for the JWK MS. It's a JWK with a validity window.
 */
/**
 * Representation of a key for the JWK MS. It's a JWK with a validity window.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@EqualsAndHashCode
@Document
public class JwkMsKey {
    @Id
    @Indexed
    public String kid;
    public String keystoreAlias;
    public String caId;
    public String algorithm;
    @JsonDeserialize(using = KeyUseDeserializer.class)
    @JsonSerialize(using = KeyUseSerializer.class)
    public KeyUse keyUse;
    @JsonIgnore
    public String jwkSerialized;

    @JsonDeserialize(using = IsoDateTimeDeserializer.class)
    @JsonSerialize(using = IsoDateTimeSerializer.class)
    public DateTime validityWindowStart;

    @JsonDeserialize(using = IsoDateTimeDeserializer.class)
    @JsonSerialize(using = IsoDateTimeSerializer.class)
    public DateTime validityWindowStop;

    @CreatedDate
    public DateTime created;
    @LastModifiedDate
    public DateTime updated;

    @JsonSerialize(using = JWKSerializer.class)
    public JWK getJwk() {
        try {
            return JWK.parse(jwkSerialized);
        } catch (ParseException e) {
            throw new RuntimeException("Serialized JWK '" + jwkSerialized + "' doesn't seems to be a JWK");
        }
    }

    @JsonDeserialize(using = JWKDeserializer.class)
    public void setJwk(JWK jwk) {
        if (jwk != null) {
            this.jwkSerialized = jwk.toJSONString();
        }
    }

    @JsonIgnore
    public Algorithm getAlgorithm() {
        if (KeyUse.SIGNATURE.equals(keyUse)) {
            return JWSAlgorithm.parse(algorithm);
        }
        if (KeyUse.ENCRYPTION.equals(keyUse)) {
            return JWEAlgorithm.parse(algorithm);
        }
        return JWSAlgorithm.parse(algorithm);
    }

    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm.getName();
    }
}
