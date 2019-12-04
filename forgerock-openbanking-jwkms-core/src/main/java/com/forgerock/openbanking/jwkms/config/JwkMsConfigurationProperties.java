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
package com.forgerock.openbanking.jwkms.config;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


/**
 * The POJO representing the JWKms configuration
 */
@Service
@ConfigurationProperties(prefix = "jwkms")
@Slf4j
@Data
public class JwkMsConfigurationProperties {

    @Data
    public static class CryptoConfig {
        public String algorithm;
    }

    @Data
    public static class Certificate {
        public String cn;
        public String ou;
        public String o;
        public String l;
        public String st;
        public String c;
    }

    @Data
    public static class Rotation {
        public long transport;
        public long keys;

        public Duration getTransportDuration() {
            return Duration.millis(transport);
        }

        public Duration getKeysDuration() {
            return Duration.millis(keys);
        }
    }

    @Data
    public static class ForgeRockApplication {
        public String name;
        public List<String> group;
        public String signingKey;
        public String encryptionKey;
        public String transportKey;
    }

    private String certificateAuthorityAlias;
    private Resource jwkKeyStore;
    private String jwkKeyStorePassword;
    public String rotationScheduler;
    public CryptoConfig signing;
    public CryptoConfig encryption;
    public String encryptionMethod;
    public CryptoConfig transport;
    public Long ExpirationWindowInMillis;
    public Certificate certificate;
    public String jwkMsId;
    public String tan;

    public String forgeRockDirectoryAppId;
    public Rotation rotation;

    public List<ForgeRockApplication> forgeRockApplications;

    public JWSAlgorithm getJWSAlgorithm() {
        return JWSAlgorithm.parse(signing.getAlgorithm());
    }

    public JWEAlgorithm getJWEAlgorithm() {
        return JWEAlgorithm.parse(encryption.getAlgorithm());
    }

    public EncryptionMethod getEncryptionMethod() {
        return EncryptionMethod.parse(encryptionMethod);
    }

    public JWSAlgorithm getTransportJWSAlgorithm() {
        return JWSAlgorithm.parse(transport.getAlgorithm());
    }

    public Optional<ForgeRockApplication> getApp(String name) {
        return forgeRockApplications.stream().filter(app -> app.getGroup().contains(name)).findAny();
    }
}
