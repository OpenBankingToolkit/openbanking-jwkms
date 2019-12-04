/**
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
package com.forgerock.openbanking.core.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.serialiser.DurationSerializer;
import com.forgerock.openbanking.serialiser.IsoDateTimeDeserializer;
import com.forgerock.openbanking.serialiser.IsoDateTimeSerializer;
import com.forgerock.openbanking.serialiser.nimbus.EncryptionMethodSerializer;
import com.forgerock.openbanking.serialiser.nimbus.JweAlgorithmSerializer;
import com.forgerock.openbanking.serialiser.nimbus.JwsAlgorithmSerializer;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.EqualsAndHashCode;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.HashMap;
import java.util.Map;

/**
 * Representation of the application
 */
@EqualsAndHashCode
@Document
public class Application {

    @Id
    @Indexed
    public String issuerId;
    public String certificateAuthorityId;

    public String defaultSigningAlgorithm;
    public String defaultEncryptionAlgorithm;
    public String defaultEncryptionMethod;

    public Long expirationWindow;

    public CertificateConfiguration certificateConfiguration;

    @Indexed
    public String currentSignKid;
    @Indexed
    public String currentEncKid;
    public Map<String, JwkMsKey> keys = new HashMap<>();

    public String defaultTransportSigningAlgorithm;
    @Indexed
    public String currentTransportKid;
    @Indexed
    public String currentTransportKeyHash;
    public Map<String, JwkMsKey> transportKeys = new HashMap<>();


    public Long transportKeysRotationPeriod;
    public Long signingAndEncryptionKeysRotationPeriod;
    @JsonDeserialize(using = IsoDateTimeDeserializer.class)
    @JsonSerialize(using = IsoDateTimeSerializer.class)
    public DateTime transportKeysNextRotation;
    @JsonDeserialize(using = IsoDateTimeDeserializer.class)
    @JsonSerialize(using = IsoDateTimeSerializer.class)
    public DateTime signingAndEncryptionKeysNextRotation;

    @JsonIgnore
    public JwkMsKey getCurrentSigningKey() {
        return this.keys.get(this.getCurrentSignKid());
    }

    @JsonIgnore
    public JwkMsKey getCurrentEncryptionKey() {
        return this.keys.get(this.getCurrentEncKid());
    }

    @JsonIgnore
    public JwkMsKey getCurrentTransportKey() {
        return this.transportKeys.get(this.getCurrentTransportKid());
    }
    /*
     * Getter and Setter
     */
    public String getIssuerId() {
        return issuerId;
    }

    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }

    public String getCurrentSignKid() {
        return currentSignKid;
    }

    public void setCurrentSignKid(String currentSignKid) {
        this.currentSignKid = currentSignKid;
    }

    public String getCurrentEncKid() {
        return currentEncKid;
    }

    public void setCurrentEncKid(String currentEncKid) {
        this.currentEncKid = currentEncKid;
    }

    public Map<String, JwkMsKey> getKeys() {
        return keys;
    }

    public void setKeys(Map<String, JwkMsKey> keys) {
        this.keys = keys;
    }

    public void addSignEncKey(JwkMsKey key) {
        this.keys.put(key.getKid(), key);
    }

    @JsonSerialize(using = JwsAlgorithmSerializer.class)
    public JWSAlgorithm getDefaultSigningAlgorithm() {
        return JWSAlgorithm.parse(defaultSigningAlgorithm);
    }

    public void setDefaultSigningAlgorithm(JWSAlgorithm defaultSigningAlgorithm) {
        this.defaultSigningAlgorithm = defaultSigningAlgorithm.getName();
    }

    @JsonSerialize(using = JweAlgorithmSerializer.class)
    public JWEAlgorithm getDefaultEncryptionAlgorithm() {
        return JWEAlgorithm.parse(defaultEncryptionAlgorithm);
    }

    public void setDefaultEncryptionAlgorithm(JWEAlgorithm defaultEncryptionAlgorithm) {
        this.defaultEncryptionAlgorithm = defaultEncryptionAlgorithm.getName();
    }

    @JsonSerialize(using = EncryptionMethodSerializer.class)
    public EncryptionMethod getDefaultEncryptionMethod() {
        return EncryptionMethod.parse(defaultEncryptionMethod);
    }

    public void setDefaultEncryptionMethod(EncryptionMethod defaultEncryptionMethod) {
        this.defaultEncryptionMethod = defaultEncryptionMethod.getName();
    }

    public CertificateConfiguration getCertificateConfiguration() {
        return certificateConfiguration;
    }

    public void setCertificateConfiguration(CertificateConfiguration certificateConfiguration) {
        this.certificateConfiguration = certificateConfiguration;
    }

    @JsonSerialize(using = JwsAlgorithmSerializer.class)
    public JWSAlgorithm getDefaultTransportSigningAlgorithm() {
        return JWSAlgorithm.parse(defaultTransportSigningAlgorithm);
    }

    public void setDefaultTransportSigningAlgorithm(JWSAlgorithm defaultTransportSigningAlgorithm) {
        this.defaultTransportSigningAlgorithm = defaultTransportSigningAlgorithm.getName();
    }

    public Map<String, JwkMsKey> getTransportKeys() {
        return transportKeys;
    }

    public JwkMsKey getKey(String kid) {
        if (getTransportKeys().containsKey(kid)) {
            return getTransportKeys().get(kid);
        } else if (getKeys().containsKey(kid)) {
            return getKeys().get(kid);
        }
        return null;
    }

    public void addTransportKey(JwkMsKey key) {
        transportKeys.put(key.getKid(), key);
    }

    public void setTransportKeys(Map<String, JwkMsKey> transportKeys) {
        this.transportKeys = transportKeys;
    }

    public String getCertificateAuthorityId() {
        return certificateAuthorityId;
    }

    public void setCertificateAuthorityId(String certificateAuthorityId) {
        this.certificateAuthorityId = certificateAuthorityId;
    }

    @JsonSerialize(using = DurationSerializer.class)
    public Duration getExpirationWindow() {
        return Duration.millis(expirationWindow);
    }

    public void setExpirationWindow(Duration expirationWindow) {
        this.expirationWindow = expirationWindow.getMillis();
    }

    public String getCurrentTransportKid() {
        return currentTransportKid;
    }

    public void setCurrentTransportKid(String currentTransportKid) {
        this.currentTransportKid = currentTransportKid;
    }

    @JsonIgnore
    public Duration getTransportKeysRotationPeriod() {
        if (transportKeysRotationPeriod == null) {
            return null;
        }
        return  Duration.millis(transportKeysRotationPeriod);
    }

    public void setTransportKeysRotationPeriod(Duration transportKeysRotationPeriod) {
        this.transportKeysRotationPeriod = transportKeysRotationPeriod.getMillis();
    }

    @JsonIgnore
    public Duration getSigningAndEncryptionKeysRotationPeriod() {
        if (signingAndEncryptionKeysRotationPeriod == null) {
            return null;
        }
        return Duration.millis(signingAndEncryptionKeysRotationPeriod);
    }

    public void setSigningAndEncryptionKeysRotationPeriod(Duration signingAndEncryptionKeysRotationPeriod) {
        this.signingAndEncryptionKeysRotationPeriod = signingAndEncryptionKeysRotationPeriod.getMillis();
    }

    public DateTime getTransportKeysNextRotation() {
        return transportKeysNextRotation;
    }

    public void setTransportKeysNextRotation(DateTime transportKeysNextRotation) {
        this.transportKeysNextRotation = transportKeysNextRotation;
    }

    public DateTime getSigningAndEncryptionKeysNextRotation() {
        return signingAndEncryptionKeysNextRotation;
    }

    public void setSigningAndEncryptionKeysNextRotation(DateTime signingAndEncryptionKeysNextRotation) {
        this.signingAndEncryptionKeysNextRotation = signingAndEncryptionKeysNextRotation;
    }

    public String getCurrentTransportKeyHash() {
        return currentTransportKeyHash;
    }

    public void setCurrentTransportKeyHash(String currentTransportKeyHash) {
        this.currentTransportKeyHash = currentTransportKeyHash;
    }

    @Override
    public String toString() {
        return "Application{" +
                "issuerId='" + issuerId + '\'' +
                ", certificateAuthorityId='" + certificateAuthorityId + '\'' +
                ", defaultSigningAlgorithm='" + defaultSigningAlgorithm + '\'' +
                ", defaultEncryptionAlgorithm='" + defaultEncryptionAlgorithm + '\'' +
                ", defaultEncryptionMethod='" + defaultEncryptionMethod + '\'' +
                ", expirationWindow=" + expirationWindow +
                ", certificateConfiguration=" + certificateConfiguration +
                ", currentSignKid='" + currentSignKid + '\'' +
                ", currentEncKid='" + currentEncKid + '\'' +
                ", keys=" + keys.size() +
                ", defaultTransportSigningAlgorithm='" + defaultTransportSigningAlgorithm + '\'' +
                ", currentTransportKid='" + currentTransportKid + '\'' +
                ", transportKeys=" + transportKeys.size() +
                ", transportKeysRotationPeriod=" + transportKeysRotationPeriod +
                ", signingAndEncryptionKeysRotationPeriod=" + signingAndEncryptionKeysRotationPeriod +
                ", transportKeysNextRotation=" + transportKeysNextRotation +
                ", signingAndEncryptionKeysNextRotation=" + signingAndEncryptionKeysNextRotation +
                '}';
    }
}
