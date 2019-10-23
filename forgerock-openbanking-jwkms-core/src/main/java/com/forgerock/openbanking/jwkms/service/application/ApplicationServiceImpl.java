/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.service.application;

import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.ForgeRockApplication;
import com.forgerock.openbanking.core.model.JwkMsKey;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.ForgeRockApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.jwkstore.JwkStoreService;
import com.forgerock.openbanking.model.ApplicationIdentity;
import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.openbanking.ssl.model.csr.CSRGenerationResponse;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
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
    @Autowired
    private JwkMsConfigurationProperties jwkMsConfigurationProperties;
    @Autowired
    private ForgeRockApplicationsRepository forgeRockApplicationsRepository;
    @Autowired
    private ApplicationService applicationService;

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

    @Override
    public Application getApplication(String username) {
        Application application;
        Optional<JwkMsConfigurationProperties.ForgeRockApplication> app = jwkMsConfigurationProperties.getApp(username);
        String name = username;
        if (app.isPresent()) {
            name = app.get().getName();
        }

        Optional<ForgeRockApplication> isApp = forgeRockApplicationsRepository.findById(name);
        if (!isApp.isPresent()) {
            Application applicationRequest = new Application();
            CertificateConfiguration certificateConfiguration = new CertificateConfiguration();
            certificateConfiguration.setCn(name);
            applicationRequest.setCertificateConfiguration(certificateConfiguration);
            application = applicationsRepository.save(createApplication(applicationRequest));

            ForgeRockApplication forgeRockApplication = new ForgeRockApplication();
            forgeRockApplication.setApplicationId(application.getIssuerId());
            forgeRockApplication.setName(name);
            forgeRockApplicationsRepository.save(forgeRockApplication);

        } else {
            application = applicationsRepository.findById(isApp.get().getApplicationId()).get();
        }
        if (app.isPresent()) {
            application = updateJWKMSApplicationFromForgeRockAppConfig(name, app.get(), application);
        }
        return application;
    }

    @Override
    public Application createApplication(Application applicationRequest) {
        Application application = new Application();

        application.setCertificateConfiguration(applicationRequest.getCertificateConfiguration());

        if (applicationRequest.defaultSigningAlgorithm == null) {
            application.setDefaultSigningAlgorithm(jwkMsConfigurationProperties.getJWSAlgorithm());
        } else {
            application.setDefaultSigningAlgorithm(applicationRequest.getDefaultSigningAlgorithm());
        }

        if (applicationRequest.defaultEncryptionAlgorithm == null) {
            application.setDefaultEncryptionAlgorithm(jwkMsConfigurationProperties.getJWEAlgorithm());
        } else {
            application.setDefaultEncryptionAlgorithm(applicationRequest.getDefaultEncryptionAlgorithm());
        }

        if (applicationRequest.defaultEncryptionMethod == null) {
            application.setDefaultEncryptionMethod(jwkMsConfigurationProperties.getEncryptionMethod());
        } else {
            application.setDefaultEncryptionMethod(applicationRequest.getDefaultEncryptionMethod());
        }

        if (applicationRequest.defaultTransportSigningAlgorithm == null) {
            application.setDefaultTransportSigningAlgorithm(jwkMsConfigurationProperties.getTransportJWSAlgorithm());
        } else {
            application.setDefaultTransportSigningAlgorithm(applicationRequest.getDefaultTransportSigningAlgorithm());
        }

        if (applicationRequest.expirationWindow == null) {
            application.setExpirationWindow(Duration.millis(jwkMsConfigurationProperties.getExpirationWindowInMillis()));
        } else {
            application.setExpirationWindow(applicationRequest.getExpirationWindow());
        }

        if (applicationRequest.getCertificateConfiguration() == null) {
            application.setCertificateConfiguration(new CertificateConfiguration());
        } else {
            application.setCertificateConfiguration(applicationRequest.getCertificateConfiguration());
        }

        if (application.getCertificateConfiguration().getCn() == null) {
            application.getCertificateConfiguration().setCn(jwkMsConfigurationProperties.getCertificate().getCn());
        }
        if (application.getCertificateConfiguration().getOu() == null) {
            application.getCertificateConfiguration().setOu(jwkMsConfigurationProperties.getCertificate().getOu());
        }
        if (application.getCertificateConfiguration().getO() == null) {
            application.getCertificateConfiguration().setO(jwkMsConfigurationProperties.getCertificate().getO());
        }
        if (application.getCertificateConfiguration().getL() == null) {
            application.getCertificateConfiguration().setL(jwkMsConfigurationProperties.getCertificate().getL());
        }
        if (application.getCertificateConfiguration().getSt() == null) {
            application.getCertificateConfiguration().setSt(jwkMsConfigurationProperties.getCertificate().getSt());
        }
        if (application.getCertificateConfiguration().getC() == null) {
            application.getCertificateConfiguration().setC(jwkMsConfigurationProperties.getCertificate().getC());
        }
        if (application.getTransportKeysRotationPeriod() == null) {
            application.setTransportKeysRotationPeriod(jwkMsConfigurationProperties.getRotation().getTransportDuration());
        }
        if (application.getSigningAndEncryptionKeysRotationPeriod() == null) {
            application.setSigningAndEncryptionKeysRotationPeriod(jwkMsConfigurationProperties.getRotation().getKeysDuration());
        }


        applicationService.resetKeys(application);
        applicationService.resetTransportKeys(application);
        return applicationsRepository.save(application);
    }

    @Override
    public Application updateJWKMSApplicationFromForgeRockAppConfig(
            String name,
            JwkMsConfigurationProperties.ForgeRockApplication forgeRockApplicationConfig,
            Application application) {
        if (forgeRockApplicationConfig.getSigningKey() != null) {
            try {
                JwkMsKey signingJwkMsKey = convertJWKToJwkMSKey(forgeRockApplicationConfig.getSigningKey());
                if (!application.getCurrentSigningKey().getKid().equals(signingJwkMsKey.getKid())) {
                    log.debug("Update the signing key for application {}", name);
                    application.getKeys().put(signingJwkMsKey.getKid(), signingJwkMsKey);
                    application.getCurrentSigningKey().setValidityWindowStop(DateTime.now());
                    application.setCurrentSignKid(signingJwkMsKey.getKid());
                } else {
                    log.debug("Same kid, no need to upgrade the signing key for application {}", name);
                }
            } catch (ParseException e) {
                log.warn("Can't parse signing JWK {} for {} => Skipping this key",
                        forgeRockApplicationConfig.getSigningKey(), name, e);
            }
        }

        if (forgeRockApplicationConfig.getEncryptionKey() != null) {
            try {
                JwkMsKey encryptionJwkMsKey = convertJWKToJwkMSKey(forgeRockApplicationConfig.getEncryptionKey());
                if (!application.getCurrentEncryptionKey().getKid().equals(encryptionJwkMsKey.getKid())) {
                    log.debug("Update the encryption key for application {}", name);
                    application.getKeys().put(encryptionJwkMsKey.getKid(), encryptionJwkMsKey);
                    application.getCurrentEncryptionKey().setValidityWindowStop(DateTime.now());
                    application.setCurrentEncKid(encryptionJwkMsKey.getKid());
                } else {
                    log.debug("Same kid, no need to upgrade the encryption key for application {}", name);
                }
            } catch (ParseException e) {
                log.warn("Can't parse encryption JWK {} for {} => Skipping this key",
                        forgeRockApplicationConfig.getSigningKey(), name, e);
            }
        }

        if (forgeRockApplicationConfig.getTransportKey() != null) {
            try {
                JwkMsKey transportJwkMsKey = convertJWKToJwkMSKey(forgeRockApplicationConfig.getTransportKey());
                if (!application.getCurrentTransportKey().getKid().equals(transportJwkMsKey.getKid())) {
                    log.debug("Update the transport key for application {}", name);
                    application.getTransportKeys().put(transportJwkMsKey.getKid(), transportJwkMsKey);
                    application.setCurrentTransportKid(transportJwkMsKey.getKid());
                    application.getCurrentEncryptionKey().setValidityWindowStop(DateTime.now());
                    application.setCurrentTransportKeyHash(transportJwkMsKey.getJwk().getX509CertSHA256Thumbprint().toString());
                } else {
                    log.debug("Same kid, no need to upgrade the transport key for application {}", name);
                }
            } catch (ParseException e) {
                log.warn("Can't parse transport JWK {} for {} => Skipping this key",
                        forgeRockApplicationConfig.getSigningKey(), name, e);
            }
        }
        return applicationsRepository.save(application);
    }

    private JwkMsKey convertJWKToJwkMSKey(String jwkSerialised) throws ParseException {
        JWK jwk = JWK.parse(jwkSerialised);
        JwkMsKey jwkMsKey = new JwkMsKey();
        jwkMsKey.setJwk(jwk);
        jwkMsKey.setAlgorithm(jwk.getAlgorithm());
        jwkMsKey.setKeyUse(jwk.getKeyUse());
        jwkMsKey.setKid(jwk.getKeyID());
        jwkMsKey.setKeystoreAlias(jwk.getKeyID());
        jwkMsKey.setValidityWindowStart(DateTime.now());
        jwkMsKey.setValidityWindowStop(DateTime.now().plusYears(3));
        jwkMsKey.setCaId(jwk.getParsedX509CertChain().get(0).getIssuerX500Principal().getName());
        return jwkMsKey;
    }
}
