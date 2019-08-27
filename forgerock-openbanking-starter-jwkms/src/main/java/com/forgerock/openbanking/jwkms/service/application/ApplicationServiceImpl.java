/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.service.application;

import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.core.auth.OBRIRole;
import com.forgerock.openbanking.core.model.csr.CSRGenerationResponse;
import com.forgerock.openbanking.core.model.jwkms.Application;
import com.forgerock.openbanking.core.model.jwkms.ApplicationIdentity;
import com.forgerock.openbanking.core.model.jwkms.JwkMsKey;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.jwkstore.JwkStoreService;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class ApplicationServiceImpl implements ApplicationService {
    private static final Logger LOGGER = LoggerFactory.getLogger(ApplicationServiceImpl.class);

    private static Map<Algorithm, AlgorithmParameterSpec> ALGORITHMS_SPEC = new HashMap<>();

    static {
        ALGORITHMS_SPEC.put(JWSAlgorithm.ES256, Curve.P_256.toECParameterSpec());
        ALGORITHMS_SPEC.put(JWSAlgorithm.ES384, Curve.P_384.toECParameterSpec());
        ALGORITHMS_SPEC.put(JWSAlgorithm.ES512, Curve.P_521.toECParameterSpec());
    }

    @Autowired
    private JwkStoreService jwkService;
    @Autowired
    private ApplicationsRepository applicationsRepository;

    @Override
    public void rotateKeys(Application application) {

        //Initiate the validity window of the current key
        LOGGER.debug("Update the current keys to be invalid in two hours");

        application.getCurrentSigningKey().setValidityWindowStop(DateTime.now().plus(application.getExpirationWindow()));
        application.getCurrentEncryptionKey().setValidityWindowStop(DateTime.now().plus(application.getExpirationWindow()));

        //Generate new keys
        JwkMsKey signingKey = createSigingnKey(application.getDefaultSigningAlgorithm(), application.getCertificateConfiguration());
        JwkMsKey encryptionKey = createEncryptionKey(application.getDefaultEncryptionAlgorithm(), application.getCertificateConfiguration());
        application.setCurrentSignKid(signingKey.kid);
        application.setCurrentEncKid(encryptionKey.kid);
        application.addSignEncKey(signingKey);
        application.addSignEncKey(encryptionKey);
        application.setSigningAndEncryptionKeysNextRotation(DateTime.now().plus(application.getSigningAndEncryptionKeysRotationPeriod()));
        LOGGER.debug("application {}", application);
        applicationsRepository.save(application);
    }

    @Override
    public void deleteApplication(Application application) {
        //Initiate the validity window of the current key
        LOGGER.debug("Delete application {}", application);
        for (JwkMsKey key : application.getKeys().values()) {
            jwkService.deleteKey(key.getKeystoreAlias());
        }
        for (JwkMsKey key : application.getTransportKeys().values()) {
            jwkService.deleteKey(key.getKeystoreAlias());
        }
        applicationsRepository.delete(application);
    }

    @Override
    public void rotateTransportKeys(Application application) {
        //Initiate the validity window of the current key
        LOGGER.debug("Update the current keys to be invalid in two hours");

        application.getCurrentTransportKey().setValidityWindowStop(DateTime.now().plus(application.getExpirationWindow()));

        //Generate new keys
        JwkMsKey transportKey = createSigingnKey(application.getDefaultTransportSigningAlgorithm(), application.getCertificateConfiguration());
        application.setCurrentTransportKid(transportKey.kid);
        application.setCurrentTransportKeyHash(transportKey.getJwk().getX509CertSHA256Thumbprint().toString());
        application.addTransportKey(transportKey);
        LOGGER.debug("application {}", application);
        application.setTransportKeysNextRotation(DateTime.now().plus(application.getTransportKeysRotationPeriod()));
        applicationsRepository.save(application);
    }

    @Override
    public void resetKeys(Application application) {
        LOGGER.debug("Reset the keys for application {}", application);

        //Make sure all keys are now considered as invalid
        for (JwkMsKey keys : application.getKeys().values()) {
            if (keys.getValidityWindowStop() == null || keys.getValidityWindowStop().isAfterNow()) {
                LOGGER.debug("keys {} was still valid. We short the validity window", keys);
                keys.setValidityWindowStop(DateTime.now());
            }
        }

        //Generate new keys
        JwkMsKey signingKey = createSigingnKey(application.getDefaultSigningAlgorithm(), application.getCertificateConfiguration());
        JwkMsKey encryptionKey = createEncryptionKey(application.getDefaultEncryptionAlgorithm(), application.getCertificateConfiguration());
        application.setCurrentSignKid(signingKey.kid);
        application.setCurrentEncKid(encryptionKey.kid);
        application.addSignEncKey(signingKey);
        application.addSignEncKey(encryptionKey);
        application.setSigningAndEncryptionKeysNextRotation(DateTime.now().plus(application.getSigningAndEncryptionKeysRotationPeriod()));

        LOGGER.debug("applicationKeys {}", application);
        applicationsRepository.save(application);
    }

    @Override
    public void resetTransportKeys(Application application) {
        LOGGER.debug("Reset the keys for application {}", application);

        //Make sure all keys are now considered as invalid
        for (JwkMsKey keys : application.getTransportKeys().values()) {
            if (keys.getValidityWindowStop() == null || keys.getValidityWindowStop().isAfterNow()) {
                LOGGER.debug("keys {} was still valid. We short the validity window", keys);
                keys.setValidityWindowStop(DateTime.now());
            }
        }
        //Generate new keys
        JwkMsKey transportKey = createSigingnKey(application.getDefaultTransportSigningAlgorithm(), application.getCertificateConfiguration());
        application.setCurrentTransportKid(transportKey.kid);
        application.setCurrentTransportKeyHash(transportKey.getJwk().getX509CertSHA256Thumbprint().toString());
        application.addTransportKey(transportKey);
        application.setTransportKeysNextRotation(DateTime.now().plus(application.getTransportKeysRotationPeriod()));

        LOGGER.debug("applicationKeys {}", application);
        applicationsRepository.save(application);
    }

    @Override
    public CSRGenerationResponse generateCSR(Application application, KeyUse keyUse, CertificateConfiguration certificateConfiguration) throws CertificateException {

        String alias = UUID.randomUUID().toString();
        Algorithm algorithm;
        if (KeyUse.SIGNATURE.equals(keyUse)) {
            algorithm = application.getDefaultSigningAlgorithm();
        } else if (KeyUse.ENCRYPTION.equals(keyUse)) {
            algorithm = application.getDefaultEncryptionAlgorithm();
        } else {
            algorithm = application.getDefaultSigningAlgorithm();
        }


        if ((KeyType.forAlgorithm(algorithm) == KeyType.EC)) {
            LOGGER.debug("The key needs to be a EC. algorithm {}", algorithm);
            jwkService.generateKeyPair(alias, application.getCertificateConfiguration(), algorithm, ALGORITHMS_SPEC.get(algorithm));
        } else if ((KeyType.forAlgorithm(algorithm) == KeyType.RSA)) {
            LOGGER.debug("The key needs to be a RCA. algorithm {}", algorithm);
            jwkService.generateKeyPair(alias, application.getCertificateConfiguration(), algorithm, null);
        } else {
            LOGGER.debug("Unsupported algorithm " + algorithm);
            throw new IllegalArgumentException("Unsupported algorithm " + algorithm);
        }

        return jwkService.generateCSR(alias, algorithm, certificateConfiguration, keyUse);
    }

    @Override
    public void importCSRResponse(Application application, String alias, String kid, KeyUse keyUse, String pem) throws CertificateException {
        jwkService.importPem(alias, pem);
        try {
            JwkMsKey key = useCertificateAsKey(application, alias, kid, keyUse);
            application.addSignEncKey(key);
            if (KeyUse.ENCRYPTION.equals(keyUse)) {
                application.getCurrentEncryptionKey().setValidityWindowStop(DateTime.now().plus(application.getExpirationWindow()));
                application.setCurrentEncKid(kid);
            } else {
                application.getCurrentSigningKey().setValidityWindowStop(DateTime.now().plus(application.getExpirationWindow()));
                application.setCurrentSignKid(kid);
            }

            applicationsRepository.save(application);
        } catch (KeyStoreException e) {
            throw new CertificateException(e);
        }
    }

    @Override
    public ApplicationIdentity authenticate(JWK jwk) {
        Optional<Application> isApplication = applicationsRepository.findByCurrentTransportKeyHash(jwk.getX509CertSHA256Thumbprint().toString());
        if (isApplication.isPresent()) {
            Application application = isApplication.get();
            ApplicationIdentity applicationIdentity = new ApplicationIdentity();
            applicationIdentity.addRole(OBRIRole.ROLE_JWKMS_APP);
            if (application.getCurrentTransportKey().getValidityWindowStop() != null) {
                applicationIdentity.addRole(OBRIRole.ROLE_ABOUT_EXPIRED_TRANSPORT);
            }

            applicationIdentity.setId(application.getIssuerId());
            return applicationIdentity;
        }

        /**
        for (Application application : all) {
            for (JwkMsKey jwkMsKey : application.getTransportKeys().values()) {
                if (jwkMsKey.getJwk().getX509CertSHA256Thumbprint().equals(jwk.getX509CertSHA256Thumbprint())) {
                    if (jwkMsKey.getValidityWindowStop() != null && jwkMsKey.getValidityWindowStop().isBeforeNow()) {
                        LOGGER.trace("Customer {} using a transport key {} already expired", application.getIssuerId(), jwkMsKey.getKid());
                        ApplicationIdentity applicationIdentity = new ApplicationIdentity();
                        applicationIdentity.addRole(OBRIRole.ROLE_EXPIRED_TRANSPORT);

                        applicationIdentity.setId(application.getIssuerId());
                        return applicationIdentity;
                    }
                }
            }
        }
         **/
        ApplicationIdentity applicationIdentity = new ApplicationIdentity();
        applicationIdentity.addRole(OBRIRole.ROLE_ANONYMOUS);
        applicationIdentity.setId("Anonymous");
        return applicationIdentity;
    }


    private JwkMsKey useCertificateAsKey(Application application, String alias, String kid, KeyUse keyUse) throws KeyStoreException {
        Algorithm algorithm;
        if (KeyUse.ENCRYPTION.equals(keyUse)) {
            algorithm = application.getDefaultEncryptionAlgorithm();
        } else {
            algorithm = application.getDefaultSigningAlgorithm();
        }
        KeyPair keyPair = jwkService.getKey(alias);


        JWK jwk = jwkService.toJwk(algorithm, jwkService.getCertificate(alias), kid, keyPair, keyUse);
        JwkMsKey key = new JwkMsKey();
        key.setJwk(jwk);
        key.setKid(kid);
        key.setKeystoreAlias(alias);
        key.setValidityWindowStart(DateTime.now());
        key.setKeyUse(keyUse);
        key.setAlgorithm(algorithm);
        return key;
    }

    private JwkMsKey createSigingnKey(JWSAlgorithm algorithm, CertificateConfiguration certificateConfiguration) {
        LOGGER.debug("Create a signing key with the algorithm {}", algorithm);

        String alias = UUID.randomUUID().toString();

        AlgorithmParameterSpec algorithmParameterSpec = null;
        if ((KeyType.forAlgorithm(algorithm) == KeyType.EC)) {
            LOGGER.debug("The key needs to be a EC. algorithm {}", algorithm);
            algorithmParameterSpec =  ALGORITHMS_SPEC.get(algorithm);
        } else if ((KeyType.forAlgorithm(algorithm) == KeyType.RSA)) {
            LOGGER.debug("The key needs to be a RCA. algorithm {}", algorithm);
        } else {
            LOGGER.debug("Unsupported algorithm " + algorithm);
            throw new IllegalArgumentException("Unsupported algorithm " + algorithm);
        }

        KeyPair keyPair = jwkService.generateKeyPair(alias, certificateConfiguration, algorithm, algorithmParameterSpec);
        JWK jwk =jwkService.generateJwk(algorithm, certificateConfiguration, alias, KeyUse.SIGNATURE, keyPair);
        LOGGER.debug("Generated JWK {}", jwk);

        JwkMsKey key = new JwkMsKey();
        key.setJwk(jwk);
        key.setKid(jwk.getKeyID());
        key.setKeystoreAlias(alias);
        key.setKeyUse(KeyUse.SIGNATURE);
        key.setAlgorithm(algorithm);
        key.setCreated(DateTime.now());
        key.setValidityWindowStart(DateTime.now());
        return key;
    }

    private JwkMsKey createEncryptionKey(JWEAlgorithm jweAlgorithm, CertificateConfiguration certificateConfiguration) {
        LOGGER.debug("Create an encryption key with algorithm {}", jweAlgorithm);
        LOGGER.debug("Note: we only support creating RSA key for encryption");
        String alias = UUID.randomUUID().toString();

        KeyPair keyPair = jwkService.generateKeyPair(alias, certificateConfiguration, jweAlgorithm, null);
        JWK jwk = jwkService.generateJwk(jweAlgorithm, certificateConfiguration, alias, KeyUse.ENCRYPTION, keyPair);
        JwkMsKey key = new JwkMsKey();
        key.setJwk(jwk);
        key.setKid(jwk.getKeyID());
        key.setKeystoreAlias(alias);
        key.setValidityWindowStart(DateTime.now());
        key.setAlgorithm(jweAlgorithm);
        key.setKeyUse(KeyUse.ENCRYPTION);
        key.setCreated(DateTime.now());
        LOGGER.debug("Generated JWK {}", jwk);
        return key;
    }
}
