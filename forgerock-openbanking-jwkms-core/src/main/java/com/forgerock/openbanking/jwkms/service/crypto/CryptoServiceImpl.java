/**
 * Copyright 2019 ForgeRock AS.
 *
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
package com.forgerock.openbanking.jwkms.service.crypto;

import com.forgerock.openbanking.constants.OpenBankingConstants;
import com.forgerock.openbanking.core.config.ApplicationConfiguration;
import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.JwkMsKey;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import com.forgerock.openbanking.jwkms.service.jwkstore.JwkStoreService;
import com.forgerock.openbanking.jwkms.service.token.TokenService;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import com.forgerock.openbanking.jwt.model.CreateDetachedJwtResponse;
import com.forgerock.openbanking.jwt.model.SigningRequest;
import com.forgerock.openbanking.jwt.model.ValidDetachedJwtResponse;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;

@Service
@Slf4j
public class CryptoServiceImpl implements CryptoService {

    private JwkStoreService jwkStoreService;
    private TokenService tokenService;
    private ApplicationService applicationService;
    private ApplicationsRepository applicationsRepository;
    private Map<JWSAlgorithm, Counter> signingCounterByAlgorithm = new HashMap<>();
    private Map<JWSAlgorithm, Timer> signingTimerByAlgorithm = new HashMap<>();
    private JwkMsConfigurationProperties jwkMsConfigurationProperties;

    public CryptoServiceImpl(JwkStoreService jwkStoreService, TokenService tokenService,
                             ApplicationService applicationService, ApplicationsRepository applicationsRepository,
                             JwkMsConfigurationProperties jwkMsConfigurationProperties) {
        this.jwkStoreService = jwkStoreService;
        this.tokenService = tokenService;
        this.applicationService = applicationService;
        this.applicationsRepository = applicationsRepository;
        this.jwkMsConfigurationProperties = jwkMsConfigurationProperties;
    }

    @Override
    public JWKSet getPublicJwks(Application application) {
        log.debug("Get all the JWKs for application '{}' but the public version of them. No private key information " +
                "will be returned.", application);

        if (application != null) {
            List<JWK> jwks = new ArrayList<>();
            jwks.add(application.getCurrentEncryptionKey().getJwk());
            for (JwkMsKey key: application.getKeys().values()) {
                JWK jwk = key.getJwk();
                if (jwk.getKeyUse() == KeyUse.SIGNATURE
                        && key.getValidityWindowStart().isBeforeNow()
                        && (key.getValidityWindowStop() == null || key.getValidityWindowStop().isAfterNow())
                        ) {
                    jwks.add(jwk);
                }
            }
            return new JWKSet(jwks);
        }
        return new JWKSet(new ArrayList<>());
    }

    @Override
    public JWKSet getTransportPublicJwks(Application application) {
        log.debug("Get all the transport JWKs for application '{}' but the public version of them. No private key " +
                "information will be returned.", application);

        if (application != null) {
            List<JWK> jwks = new ArrayList<>();
            for (JwkMsKey key: application.getTransportKeys().values()) {
                JWK jwk = key.getJwk();
                if (jwk.getKeyUse() == KeyUse.SIGNATURE
                        && key.getValidityWindowStart().isBeforeNow()
                        && (key.getValidityWindowStop() == null || key.getValidityWindowStop().isAfterNow())
                        ) {
                    jwks.add(jwk);
                }
            }
            return new JWKSet(jwks);
        }
        return new JWKSet(new ArrayList<>());
    }

    @Override
    public SignedJWT sign(String issuerId, JWTClaimsSet claimsSet, Application application, Boolean includeKey) {

        if (log.isDebugEnabled()) {
            log.debug("Sign the claims {} for application {}", claimsSet, application);
        }

        JWK signingJwk;
        JwkMsKey currentSigningKey = application.getCurrentSigningKey();
        try {
            signingJwk = currentSigningKey.getJwk();
            if (signingJwk == null) {
                log.debug("Couldn't find the private key for jwk '{}'. Resetting the keys as emergency solution",
                        currentSigningKey.getJwk());
                applicationService.resetKeys(application);
                signingJwk = currentSigningKey.getJwk();
            }
            log.debug("Signing JWK: {}", signingJwk);

            JWTClaimsSet.Builder claimBuilder = new JWTClaimsSet.Builder(claimsSet);
            claimBuilder.issuer(issuerId);
            claimBuilder.issueTime(new Date());
            claimBuilder.jwtID(UUID.randomUUID().toString());
            claimsSet = claimBuilder.build();

            JWSAlgorithm algorithm = (JWSAlgorithm) currentSigningKey.getAlgorithm();
            JWSHeader.Builder jwsHeaderBuilder = new JWSHeader
                    .Builder(algorithm)
                    .keyID(currentSigningKey.getKid());
            if (includeKey) {
                jwsHeaderBuilder.jwk(signingJwk.toPublicJWK());
            }
            JWSHeader jwsHeader = jwsHeaderBuilder.build();
            SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);

            return signJws(signingJwk, algorithm, signedJWT);
        } catch (JOSEException e) {
            log.error("Couldn't load the key behind the kid '{}'", currentSigningKey.getKid(), e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            log.error("Couldn't rebuild JWT", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public CreateDetachedJwtResponse signPayloadToDetachedJwt(SigningRequest signingRequest, String issuerId, String payload, Application application) {
        if (issuerId == null) {
            issuerId = application.getIssuerId();
        }
        if (log.isDebugEnabled()) {
            log.debug("Sign the payload {} for application {}", payload, application);
        }
        if (signingRequest == null) {
            signingRequest = SigningRequest.builder()
                    .customHeaderClaims(
                            SigningRequest.CustomHeaderClaims.builder()
                                    .includeB64(true)
                                    .includeOBIss(true)
                                    .includeOBIat(true)
                                    .includeCrit(true)
                                    .tan(jwkMsConfigurationProperties.getTan())
                                    .build())
                    .build();
        }

        JWK signingJwk;
        JwkMsKey currentSigningKey = application.getCurrentSigningKey();
        try {
            signingJwk = currentSigningKey.getJwk();
            if (signingJwk == null) {
                log.debug("Couldn't find the private key for jwk '{}'. Resetting the keys as emergency solution",
                        currentSigningKey.getJwk());
                applicationService.resetKeys(application);
                signingJwk = currentSigningKey.getJwk();
            }
            log.debug("Signing JWK: {}", signingJwk);


            JWSAlgorithm algorithm = (JWSAlgorithm) currentSigningKey.getAlgorithm();
            JWSHeader jwsHeader = generateJWSHeaderFromSigningRequest(signingRequest, issuerId, currentSigningKey, algorithm);
            JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(payload));

            SignedJWT signedJWT = signJws(signingJwk, algorithm, jwsObject);

            boolean isDetachedPayload = !jwsObject.getHeader().isBase64URLEncodePayload(); // a detached payload does NOT have a b64 encoded payload
            String jws = jwsObject.serialize(isDetachedPayload);
            log.debug("The resulting jws: {}", jws);
            return CreateDetachedJwtResponse.builder()
                    .detachedSignature(jws)
                    .intermediateJWSConstructedForDebug(signedJWT.serialize())
                    .build();
        } catch (JOSEException e) {
            log.error("Couldn't load the key behind the kid '{}'", currentSigningKey.getKid(), e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            log.error("Couldn't parse JWT which should not be possible", e);
            throw new RuntimeException(e);
        }
    }

    private SignedJWT signJws(JWK signingJwk, JWSAlgorithm algorithm, JWSObject jwsObject) throws JOSEException, ParseException {
        getSigningCounter(algorithm).increment();
        Timer.Sample timer = Timer.start(Metrics.globalRegistry);
        try {
            JWSSigner signer = getJwsSigner(signingJwk);
            jwsObject.sign(signer);
            return new SignedJWT(jwsObject.getHeader().toBase64URL(), jwsObject.getPayload().toBase64URL(), jwsObject.getSignature());
        } finally {
            timer.stop(getSigningTimer(algorithm));
        }
    }

    private JWSSigner getJwsSigner(JWK signingJwk) throws JOSEException {
        KeyPair keyPairFromJWK = getKeyPairFromJWK(signingJwk);
        JWSSigner signer;
        if (keyPairFromJWK.getPrivate() instanceof ECPrivateKey) {
            signer = new ECDSASigner((ECPrivateKey) getKeyPairFromJWK(signingJwk).getPrivate());
        } else if (keyPairFromJWK.getPrivate() instanceof RSAPrivateKey) {
            signer = new RSASSASigner(getKeyPairFromJWK(signingJwk).getPrivate());
        } else {
            log.error("Unknown algorithm '{}' used for generate the key {}", keyPairFromJWK.getPrivate().getClass(), signingJwk.getKeyID());
            throw new RuntimeException("Unknown algorithm '" + keyPairFromJWK.getPrivate().getClass() + "' used for generate the key '" + signingJwk.getKeyID() + "'");
        }
        return signer;
    }

    private JWSHeader generateJWSHeaderFromSigningRequest(SigningRequest signingRequest, String issuerId, JwkMsKey currentSigningKey, JWSAlgorithm algorithm) {
        JWSHeader.Builder headerBuilder = new JWSHeader
                .Builder(algorithm)
                .keyID(currentSigningKey.getKid());
        List<String> customHeaderClaims = new ArrayList<>();
        if (signingRequest.getCustomHeaderClaims().isIncludeB64()) {
            headerBuilder.base64URLEncodePayload(false);
            customHeaderClaims.add(OpenBankingConstants.OBJwtHeaderClaims.B64);
        }
        if (signingRequest.getCustomHeaderClaims().isIncludeOBIss()) {
            headerBuilder.customParam(OpenBankingConstants.OBJwtHeaderClaims.OB_ISS, issuerId);
            customHeaderClaims.add(OpenBankingConstants.OBJwtHeaderClaims.OB_ISS);
        }
        if (signingRequest.getCustomHeaderClaims().isIncludeOBIat()) {
            headerBuilder.customParam(OpenBankingConstants.OBJwtHeaderClaims.OB_IAT, DateUtils.toSecondsSinceEpoch(new Date()));
            customHeaderClaims.add(OpenBankingConstants.OBJwtHeaderClaims.OB_IAT);
        }
        if (signingRequest.getCustomHeaderClaims().getTan() != null) {
            headerBuilder.customParam(OpenBankingConstants.OBJwtHeaderClaims.OB_TAN, signingRequest.getCustomHeaderClaims().getTan());
            customHeaderClaims.add(OpenBankingConstants.OBJwtHeaderClaims.OB_TAN);
        }
        if (signingRequest.getCustomHeaderClaims().isIncludeCrit() && !customHeaderClaims.isEmpty()) {
            headerBuilder.criticalParams(new HashSet<>(customHeaderClaims));
        }

        return headerBuilder.build();
    }

    @Override
    public EncryptedJWT signAndEncrypt(String issuerId, JWTClaimsSet claimsSet, RSAKey jwkForEncryption, Application applicationKeys, Boolean includeKey)
            throws JOSEException {

        if (log.isDebugEnabled()) {
            log.debug("Sign the claims {} by {} and encrypt them with {}", claimsSet, applicationKeys, jwkForEncryption);
        }
        return encrypt(sign(issuerId, claimsSet, applicationKeys, includeKey), jwkForEncryption);
    }

    @Override
    public SignedJWT decrypt(EncryptedJWT encryptedJWT, Application application) {
        JwkMsKey key = application.getKeys().get(encryptedJWT.getHeader().getKeyID());
        if (key == null) {
            log.debug("Failed to find JWK for the following kid='{}'", encryptedJWT.getHeader().getKeyID());
            throw new IllegalArgumentException("Failed to find JWK for the following kid='"
                    + encryptedJWT.getHeader().getKeyID() + "'");
        }
        log.debug("In order to decrypt the JWE, we need to find the private key behind our public key used " +
                "by the third party.");
        try {
            JWK jwk = application.getCurrentEncryptionKey().getJwk();
            if (jwk == null) {
                log.error("Couldn't find the private key corresponding to '{}'. Resetting the keys as emergency " +
                        "solution", application.getCurrentEncryptionKey().getJwk());
                applicationService.resetKeys(application);
                return null;
            }

            JWEDecrypter decrypter = new RSADecrypter((RSAKey) jwk);
            encryptedJWT.decrypt(decrypter);
            return encryptedJWT.getPayload().toSignedJWT();
        } catch (JOSEException e) {
            log.error("JWE object couldn't be decrypted", e);
            return null;
        }
    }

    @Override
    public void validate(SignedJWT signedJWT, String expectedAudienceId, Application applicationTo) throws InvalidTokenException,
            ParseException {

        final String audienceId;
        if (expectedAudienceId == null) {
            audienceId = applicationTo.getIssuerId();
        } else {
            audienceId = expectedAudienceId;
        }
        String issuer = signedJWT.getJWTClaimsSet().getIssuer();
        if (log.isDebugEnabled()) {
            log.debug("Validate the jws {} that has been signed for app {}", signedJWT.serialize(), applicationTo);
        }
        Optional<Application> isApplicationFrom = applicationsRepository.findById(issuer);
        if (!isApplicationFrom.isPresent()) {
            throw new InvalidTokenException("Application '" + issuer + "' not found");
        }
        Application applicationFrom = isApplicationFrom.get();
        //The idea is that we retrieve the app that generated this JWT, 'applicationFrom'
        ApplicationConfiguration from = new ApplicationConfiguration() {
            @Override
            public String getIssuerID() {
                return applicationFrom.getIssuerId();
            }

            @Override
            public JWKSet getJwkSet() {
                return getPublicJwks(applicationFrom);
            }
        };
        ApplicationConfiguration to = null;
        //And we make sure the destination application 'applicationTo' was indeed an audience of it.
        if (!issuer.equals(applicationTo.getIssuerId())) {
            to = new ApplicationConfiguration() {
                @Override
                public String getIssuerID() {
                    return audienceId;
                }

                @Override
                public JWKSet getJwkSet() {
                    return getPublicJwks(applicationTo);
                }

                @Override
                public String toString() {
                    return "'" + getIssuerID() + "'-'" + applicationTo + "'";
                }
            };
        }
        tokenService.validateToken(signedJWT, from, to);
    }

    @Override
    public void validate(SignedJWT signedJWT, String issuerId, String jwkUri) throws InvalidTokenException,
            ParseException, IOException {

        if (log.isDebugEnabled()) {
            log.debug("Validate the jws {} that has been signed for app with jwk uri {}", signedJWT.serialize(), jwkUri);
        }
        JWKSet jwkSet = JWKSet.load(new URL(jwkUri));
        ApplicationConfiguration from = new ApplicationConfiguration() {
            @Override
            public String getIssuerID() {
                return issuerId;
            }

            @Override
            public JWKSet getJwkSet() {
                return jwkSet;
            }
        };
        tokenService.validateToken(signedJWT, from, null);
    }

    @Override
    public void validate(SignedJWT signedJWT, String issuerId, JWK jwk) throws InvalidTokenException {

        if (log.isDebugEnabled()) {
            log.debug("Validate the jws {} that has been signed for app with jwk {}", signedJWT.serialize(), jwk.toJSONString());
        }
        JWKSet jwkSet = new JWKSet(jwk);
        ApplicationConfiguration from = new ApplicationConfiguration() {
            @Override
            public String getIssuerID() {
                return issuerId;
            }

            @Override
            public JWKSet getJwkSet() {
                return jwkSet;
            }
        };
        tokenService.validateToken(signedJWT, from, null);
    }

    @Override
    public ValidDetachedJwtResponse validateDetachedJwS(SignedJWT signedJWT, String expectedIssuerId) {
        String issuerId = (String) signedJWT.getHeader().getCustomParam(OpenBankingConstants.OBJwtHeaderClaims.OB_ISS);
        ValidDetachedJwtResponse.ValidDetachedJwtResponseBuilder builder = ValidDetachedJwtResponse.builder()
                .reconstructJWS(signedJWT.serialize());

        try {
            Optional<Application> isApplicationFrom = applicationsRepository.findById(issuerId);
            if (!isApplicationFrom.isPresent()) {
                throw new InvalidTokenException("Application '" + issuerId + "' not found");
            }
            Application applicationFrom = isApplicationFrom.get();
            ApplicationConfiguration from = new ApplicationConfiguration() {
                public String getIssuerID() {
                    return applicationFrom.getIssuerId();
                }

                @Override
                public JWKSet getJwkSet() {
                    return getPublicJwks(applicationFrom);
                }
            };

            tokenService.validateDetachedToken(signedJWT, from, null);
            builder.isValid(true);
        } catch (InvalidTokenException e) {
            log.debug("JWT {} is invalid", signedJWT.serialize(), e);
            builder.isValid(false);
            builder.message(e.getMessage());
        }
        return builder.build();
    }

    @Override
    public ValidDetachedJwtResponse validateDetachedJwS(SignedJWT signedJWT, String issuerId, String jwkUri)
            throws ParseException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("Validate the detached jws {} that has been signed for app with jwk uri {}", signedJWT.serialize(), jwkUri);
        }
        JWKSet jwkSet = JWKSet.load(new URL(jwkUri));
        ApplicationConfiguration from = new ApplicationConfiguration() {
            @Override
            public String getIssuerID() {
                return issuerId;
            }

            @Override
            public JWKSet getJwkSet() {
                return jwkSet;
            }
        };
        ValidDetachedJwtResponse.ValidDetachedJwtResponseBuilder builder = ValidDetachedJwtResponse.builder()
                .reconstructJWS(signedJWT.serialize());
        try {
            tokenService.validateDetachedToken(signedJWT, from, null);
            builder.isValid(true);
        } catch (InvalidTokenException e) {
            log.debug("JWT {} is invalid", signedJWT.serialize(), e);
            builder.isValid(false);
            builder.message(e.getMessage());
        }
        return builder.build();
    }

    @Override
    public ValidDetachedJwtResponse validateDetachedJwSWithJWK(SignedJWT signedJWT, String issuerId, String jwk)
            throws ParseException {
        if (log.isDebugEnabled()) {
            log.debug("Validate the detached jws {} that has been signed for app with jwk {}", signedJWT.serialize(), jwk);
        }
        JWKSet jwkSet = new JWKSet(JWK.parse(jwk));
        ApplicationConfiguration from = new ApplicationConfiguration() {
            @Override
            public String getIssuerID() {
                return issuerId;
            }

            @Override
            public JWKSet getJwkSet() {
                return jwkSet;
            }
        };
        ValidDetachedJwtResponse.ValidDetachedJwtResponseBuilder builder = ValidDetachedJwtResponse.builder()
                .reconstructJWS(signedJWT.serialize());
        try {
            tokenService.validateDetachedToken(signedJWT, from, null);
            builder.isValid(true);
        } catch (InvalidTokenException e) {
            log.debug("JWT {} is invalid", signedJWT.serialize(), e);
            builder.isValid(false);
            builder.message(e.getMessage());
        }
        return builder.build();
    }


    private static KeyPair getKeyPairFromJWK(JWK jwk) {
        log.debug("Get keypair for JWK {}", jwk);
        try {
            if (KeyType.RSA == jwk.getKeyType()) {
                log.debug("The JWK is a RSA key");
                RSAKey rsaKey = (RSAKey) jwk;
                return new KeyPair(rsaKey.toPublicKey(), rsaKey.toPrivateKey());
            } else if (KeyType.EC == jwk.getKeyType()) {
                log.debug("The JWK is an EC key");
                ECKey ecKey = (ECKey) jwk;
                return new KeyPair(ecKey.toPublicKey(), ecKey.toPrivateKey());
            } else {
                log.debug("Not implemented JWT type '" + jwk.getKeyType() + "'");
                throw new IllegalArgumentException("Not implemented JWT type '" + jwk.getKeyType() + "'");
            }
        } catch (JOSEException e) {
            log.error("Error when loading the keypair from the JWK. kid='{}'", jwk.getKeyID(), e);
            throw new RuntimeException(e);
        }
    }

    private EncryptedJWT encrypt(SignedJWT signedJWT, RSAKey jwkForEncryption) throws JOSEException {
        log.debug("Encrypt the JWS '{}' with a RSA key", signedJWT.serialize());
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.parse(jwkForEncryption.getAlgorithm().getName()),
                EncryptionMethod.A128CBC_HS256).keyID(jwkForEncryption.getKeyID()).build();
        JWEObject jweObject = new JWEObject(header, new Payload(signedJWT));

        // Create an encrypter with the specified public RSA key
        RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) getKeyPairFromJWK(jwkForEncryption).getPublic());
        encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
        jweObject.encrypt(encrypter);
        try {
            return EncryptedJWT.parse(jweObject.serialize());
        } catch (ParseException e) {
            log.error("Couldn't parse the jwe", e);
            throw new RuntimeException(e);
        }
    }

    private Counter getSigningCounter(JWSAlgorithm algorithm) {
        if (!signingCounterByAlgorithm.containsKey(algorithm)) {
            signingCounterByAlgorithm.put(algorithm, Metrics.counter("crypto.signing.counter", "algorithm", algorithm.getName()));
        }
        return signingCounterByAlgorithm.get(algorithm);
    }

    private Timer getSigningTimer(JWSAlgorithm algorithm) {
        if (!signingTimerByAlgorithm.containsKey(algorithm)) {
            signingTimerByAlgorithm.put(algorithm, Metrics.timer("crypto.signing.timer", "algorithm", algorithm.getName()));
        }
        return signingTimerByAlgorithm.get(algorithm);
    }
}
