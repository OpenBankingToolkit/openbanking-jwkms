/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.api.application;

import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.ApplicationIdentity;
import com.forgerock.openbanking.core.model.ForgeRockApplication;
import com.forgerock.openbanking.core.model.JwkMsKey;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.ForgeRockApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.SoftwareStatementRepository;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import com.forgerock.openbanking.jwkms.service.crypto.CryptoService;
import com.forgerock.openbanking.jwkms.service.keystore.JwkKeyStoreService;
import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.openbanking.model.SoftwareStatement;
import com.forgerock.openbanking.ssl.model.ForgeRockApplicationResponse;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.Principal;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/application")
@Slf4j
public class ApplicationApiController implements ApplicationApi {
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    @Autowired
    private ApplicationsRepository applicationsRepository;
    @Autowired
    private ForgeRockApplicationsRepository forgeRockApplicationsRepository;
    @Autowired
    private ApplicationService applicationService;
    @Autowired
    private CryptoService cryptoService;
    @Autowired
    private JwkMsConfigurationProperties jwkMsConfigurationProperties;
    @Autowired
    private JwkKeyStoreService jwkKeyStoreService;
    @Autowired
    private SoftwareStatementRepository softwareStatementRepository;

    @Override
    public ResponseEntity<List<Application>> getAllApplication() {
        return ResponseEntity.ok(applicationsRepository.findAll());
    }

    @Override
    public ResponseEntity read(@PathVariable String appId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        return ResponseEntity.ok(isApplication.get());
    }

    @Override
    @RequestMapping(value = "/", method = RequestMethod.POST)
    public ResponseEntity<Application> create(@RequestBody Application applicationRequest) {
        log.debug("Create a new application");
        try {
            return ResponseEntity.ok(createApplication(applicationRequest));
        } finally {
            log.debug("Application created");
        }
    }

    @Override
    @RequestMapping(value = "/{applicationId}", method = RequestMethod.DELETE)
    public ResponseEntity delete(@PathVariable(value = "applicationId") String applicationId) {
        deleteApplication(applicationId);
        return ResponseEntity.ok().build();

    }

    @RequestMapping(value = "/{appId}/transport/jwk_uri", method = RequestMethod.GET)
    @Override
    public ResponseEntity transportKeysJwkUri(@PathVariable String appId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        return ResponseEntity.ok(cryptoService.getTransportPublicJwks(isApplication.get()).toJSONObject().toJSONString());
    }

    @RequestMapping(value = "/{appId}/transport/rotate", method = RequestMethod.PUT)
    @Override
    public ResponseEntity transportKeysRotate(@PathVariable String appId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        Application application = isApplication.get();
        applicationService.rotateTransportKeys(application);
        return ResponseEntity.ok(application);
    }

    @RequestMapping(value = "/{appId}/transport/reset", method = RequestMethod.PUT)
    @Override
    public ResponseEntity transportKeysReset(@PathVariable String appId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        Application application = isApplication.get();
        applicationService.resetTransportKeys(application);
        return ResponseEntity.ok(application);
    }

    @Override
    public ResponseEntity signingEncryptionKeysJwkUri(@PathVariable String appId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        return ResponseEntity.ok(cryptoService.getPublicJwks(isApplication.get()).toJSONObject().toJSONString());
    }

    @RequestMapping(value = "/{appId}/rotate", method = RequestMethod.PUT)
    @Override
    public ResponseEntity signingEncryptionKeysRotate(@PathVariable String appId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        Application application = isApplication.get();
        applicationService.rotateKeys(application);
        return ResponseEntity.ok(application);
    }

    @RequestMapping(value = "/{appId}/reset", method = RequestMethod.PUT)
    @Override
    public ResponseEntity signingEncryptionKeysReset(@PathVariable String appId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        Application application = isApplication.get();
        applicationService.resetKeys(application);
        return ResponseEntity.ok(application);
    }

    @RequestMapping(value = "/{appId}/key/{keyId}", method = RequestMethod.PUT)
    @Override
    public ResponseEntity getKey(@PathVariable(name = "appId") String appId, @PathVariable(name = "keyId") String keyId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        Application application = isApplication.get();
        return ResponseEntity.ok(application.getKey(keyId).getJwk().toJSONString());
    }


    @RequestMapping(value = "/{appId}/key/{keyId}/certificate/public/", method = RequestMethod.PUT)
    @Override
    public ResponseEntity<String> getPublicCertificate(@PathVariable(name = "appId") String appId, @PathVariable(name = "keyId") String keyId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        Application application = isApplication.get();
        PrintStream ps = null;
        ByteArrayOutputStream bs = null;
        try {
            JwkMsKey key = application.getKey(keyId);
            if (key != null) {
                bs = new ByteArrayOutputStream();
                ps = new PrintStream(bs);
                Base64 base64Cert = key.getJwk().getX509CertChain().get(0);

                ps.println(BEGIN_CERT);
                String certEncoded = Base64.encode(base64Cert.decode()).toString().replaceAll("(.{64})", "$1\n");
                ps.println(certEncoded);
                ps.println(END_CERT);
                return ResponseEntity.ok(new String(bs.toByteArray()));
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Key '" + keyId + "' can't be found.");
            }
        } finally {
            if (ps != null) {
                ps.close();
            }
            if (bs != null) {
                try {
                    bs.close();
                } catch (IOException e) {
                    log.error("Couldn't close properly ByteArrayOutputStream", e);
                }
            }
        }
    }

    @RequestMapping(value = "/{appId}/key/{keyId}/certificate/private/", method = RequestMethod.PUT)
    @Override
    public ResponseEntity<String> getPrivateCertificate(@PathVariable(name = "appId") String appId, @PathVariable(name = "keyId") String keyId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        Application application = isApplication.get();
        PrintStream ps = null;
        ByteArrayOutputStream bs = null;
        try {
            JwkMsKey key = application.getKey(keyId);
            if (key != null) {
                bs = new ByteArrayOutputStream();
                ps = new PrintStream(bs);
                ps.println("-----BEGIN PRIVATE KEY-----");
                if (key.getJwk() instanceof RSAKey) {

                    ps.print(Base64.encode(((RSAKey) key.getJwk()).toKeyPair().getPrivate().getEncoded())
                            .toString().replaceAll("(.{64})", "$1\n"));
                } else if (key.getJwk() instanceof ECKey) {
                    ps.print(Base64.encode(((ECKey) key.getJwk()).toKeyPair().getPrivate().getEncoded())
                            .toString().replaceAll("(.{64})", "$1\n"));
                }
                ps.print("\n");
                ps.println("-----END PRIVATE KEY-----");
                return ResponseEntity.ok(new String(bs.toByteArray()));
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Key '" + keyId + "' can't be found.");
            }
        } catch (JOSEException e) {
            log.error("Couldn't not read keypair from JWK", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Key '" + keyId + "' can't be loaded properly.");
        } finally {
            if (ps != null) {
                ps.close();
            }
            if (bs != null) {
                try {
                    bs.close();
                } catch (IOException e) {
                    log.error("Couldn't close properly ByteArrayOutputStream", e);
                }
            }
        }
    }

    @Override
    @RequestMapping(value = "/current", method = RequestMethod.GET)
    public ResponseEntity getCurrentApplication(Principal principal) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Application application;
        if (authentication.getAuthorities().contains(OBRIRole.ROLE_FORGEROCK_INTERNAL_APP)) {

            Optional<JwkMsConfigurationProperties.ForgeRockApplication> app = jwkMsConfigurationProperties.getApp(principal.getName());
            String name = principal.getName();
            if (app.isPresent()) {
                name = app.get().getName();
            }

            Optional<ForgeRockApplication> isApp = forgeRockApplicationsRepository.findById(name);
            if (!isApp.isPresent()) {
                Application applicationRequest = new Application();
                CertificateConfiguration certificateConfiguration = new CertificateConfiguration();
                certificateConfiguration.setCn(name);
                applicationRequest.setCertificateConfiguration(certificateConfiguration);
                application = createApplication(applicationRequest);

                ForgeRockApplication forgeRockApplication = new ForgeRockApplication();
                forgeRockApplication.setApplicationId(application.getIssuerId());
                forgeRockApplication.setName(name);
                forgeRockApplicationsRepository.save(forgeRockApplication);
                SoftwareStatement softwareStatement = new SoftwareStatement();
                softwareStatement.setName(name);
                softwareStatement.setApplicationId(application.getIssuerId());
                softwareStatement.setId(application.getIssuerId());
                softwareStatementRepository.save(softwareStatement);
            } else {
                application = applicationsRepository.findById(isApp.get().getApplicationId()).get();
            }
            if (app.isPresent()) {
                application = updateJWKMSApplicationFromForgeRockAppConfig(name, app.get(), application);
            }
        } else {
            application = applicationsRepository.findById(principal.getName()).get();
        }

        ForgeRockApplicationResponse forgeRockApplicationResponse = new ForgeRockApplicationResponse();
        forgeRockApplicationResponse.setApplicationId(application.getIssuerId());
        forgeRockApplicationResponse.setTransportKey(application.getCurrentTransportKey().getJwk());

        return ResponseEntity.ok(forgeRockApplicationResponse);
    }

    @Override
    @RequestMapping(value = "/forgerock-app/{name}/jwk_uri", method = RequestMethod.GET)
    public ResponseEntity getForgeRockJwkUri(
            @PathVariable(name = "name") String name) {
        Optional<ForgeRockApplication> isApp = forgeRockApplicationsRepository.findById(name);
        if (!isApp.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ForgeRock Application '" + name + "' can't be found.");
        }
        Optional<Application> isApplication = applicationsRepository.findById(isApp.get().getApplicationId());
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Application '" + isApp.get().getApplicationId() + "' can't be found.");
        }
        return ResponseEntity.ok(cryptoService.getPublicJwks(isApplication.get()).toJSONObject().toJSONString());
    }


    private void deleteApplication(String applicationId) {
        Optional<Application> byId = applicationsRepository.findById(applicationId);
        if (byId.isPresent()) {
            applicationService.deleteApplication(byId.get());
            applicationsRepository.deleteById(applicationId);
        }
    }


    private Application createApplication(Application applicationRequest) {
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
    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity authenticate(@RequestBody String jwkSerialised) {
        try {
            log.debug("Try to authenticate '{}'", jwkSerialised);
            JWK jwk = JWK.parse(jwkSerialised);
            ApplicationIdentity authenticate = applicationService.authenticate(jwk);
            log.debug("Authenticated with success '{}'", authenticate);
            return ResponseEntity.ok(authenticate);
        } catch (ParseException e) {
            log.warn("Can't parse JWK", e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Can't parse JWK");
        }
    }


    private Application updateJWKMSApplicationFromForgeRockAppConfig(
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
