/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.config;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@ConfigurationProperties(prefix = "jwkms")
/**
 * The POJO representing the JWKms configuration
 */
public class JwkMsConfigurationProperties {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwkMsConfigurationProperties.class);

    public static class CryptoConfig {
        public String algorithm;

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }
    }

    public static class Certificate {
        public String cn;
        public String ou;
        public String o;
        public String l;
        public String st;
        public String c;

        public String getCn() {
            return cn;
        }

        public void setCn(String cn) {
            this.cn = cn;
        }

        public String getOu() {
            return ou;
        }

        public void setOu(String ou) {
            this.ou = ou;
        }

        public String getO() {
            return o;
        }

        public void setO(String o) {
            this.o = o;
        }

        public String getL() {
            return l;
        }

        public void setL(String l) {
            this.l = l;
        }

        public String getSt() {
            return st;
        }

        public void setSt(String st) {
            this.st = st;
        }

        public String getC() {
            return c;
        }

        public void setC(String c) {
            this.c = c;
        }
    }

    public static class Rotation {
        public long transport;
        public long keys;

        public long getTransport() {
            return transport;
        }

        public void setTransport(long transport) {
            this.transport = transport;
        }

        public long getKeys() {
            return keys;
        }

        public void setKeys(long keys) {
            this.keys = keys;
        }

        public Duration getTransportDuration() {
            return Duration.millis(transport);
        }

        public Duration getKeysDuration() {
            return Duration.millis(keys);
        }
    }

    public static class ForgeRockApplication {
        public String name;
        public List<String> group;
        public String signingKey;
        public String encryptionKey;
        public String transportKey;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public List<String> getGroup() {
            return group;
        }

        public void setGroup(List<String> group) {
            this.group = group;
        }

        public String getSigningKey() {
            return signingKey;
        }

        public void setSigningKey(String signingKey) {
            this.signingKey = signingKey;
        }

        public String getEncryptionKey() {
            return encryptionKey;
        }

        public void setEncryptionKey(String encryptionKey) {
            this.encryptionKey = encryptionKey;
        }

        public String getTransportKey() {
            return transportKey;
        }

        public void setTransportKey(String transportKey) {
            this.transportKey = transportKey;
        }
    }

    public String rotationScheduler;
    public CryptoConfig signing;
    public CryptoConfig encryption;
    public String encryptionMethod;
    public CryptoConfig transport;
    public Long ExpirationWindowInMillis;
    public Certificate certificate;
    public String jwkMsId;
    public String internalCAAlias;
    public String defaultCAAlias;
    public String tan;

    public String forgeRockDirectoryAppId;
    public String appAuthHeader;
    public Rotation rotation;

    public List<ForgeRockApplication> forgeRockApplications;

    /*
     * Getter and Setter
     */
    public String getRotationScheduler() {
        return rotationScheduler;
    }

    public void setRotationScheduler(String rotationScheduler) {
        this.rotationScheduler = rotationScheduler;
    }

    public CryptoConfig getSigning() {
        return signing;
    }

    public JWSAlgorithm getJWSAlgorithm() {
        return JWSAlgorithm.parse(signing.getAlgorithm());
    }

    public void setSigning(CryptoConfig signing) {
        this.signing = signing;
    }

    public CryptoConfig getEncryption() {
        return encryption;
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


    public void setEncryption(CryptoConfig encryption) {
        this.encryption = encryption;
    }

    public String getAppAuthHeader() {
        return appAuthHeader;
    }

    public void setAppAuthHeader(String appAuthHeader) {
        this.appAuthHeader = appAuthHeader;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public String getForgeRockDirectoryAppId() {
        return forgeRockDirectoryAppId;
    }

    public void setForgeRockDirectoryAppId(String forgeRockDirectoryAppId) {
        this.forgeRockDirectoryAppId = forgeRockDirectoryAppId;
    }

    public void setEncryptionMethod(String encryptionMethod) {
        this.encryptionMethod = encryptionMethod;
    }

    public CryptoConfig getTransport() {
        return transport;
    }

    public void setTransport(CryptoConfig transport) {
        this.transport = transport;
    }

    public Long getExpirationWindowInMillis() {
        return ExpirationWindowInMillis;
    }

    public void setExpirationWindowInMillis(Long expirationWindowInMillis) {
        ExpirationWindowInMillis = expirationWindowInMillis;
    }

    public String getJwkMsId() {
        return jwkMsId;
    }

    public void setJwkMsId(String jwkMsId) {
        this.jwkMsId = jwkMsId;
    }

    public Rotation getRotation() {
        return rotation;
    }

    public void setRotation(Rotation rotation) {
        this.rotation = rotation;
    }

    public String getInternalCAAlias() {
        return internalCAAlias;
    }

    public void setInternalCAAlias(String internalCAAlias) {
        this.internalCAAlias = internalCAAlias;
    }

    public String getDefaultCAAlias() {
        return defaultCAAlias;
    }

    public void setDefaultCAAlias(String defaultCAAlias) {
        this.defaultCAAlias = defaultCAAlias;
    }

    public List<ForgeRockApplication> getForgeRockApplications() {
        return forgeRockApplications;
    }

    public void setForgeRockApplications(List<ForgeRockApplication> forgeRockApplications) {
        this.forgeRockApplications = forgeRockApplications;
    }

    public Optional<ForgeRockApplication> getApp(String name) {
        return forgeRockApplications.stream().filter(app -> app.getGroup().contains(name)).findAny();
    }

    public String getTan() {
        return tan;
    }

    public void setTan(String tan) {
        this.tan = tan;
    }
}
