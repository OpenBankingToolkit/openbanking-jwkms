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
import com.forgerock.openbanking.core.model.ForgeRockApplication;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.ForgeRockApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.SoftwareStatementRepository;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import com.forgerock.openbanking.jwkms.service.crypto.CryptoService;
import com.forgerock.openbanking.jwkms.service.keystore.JwkKeyStoreService;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.forgerock.openbanking.model.ApplicationIdentity;
import com.forgerock.openbanking.model.SoftwareStatement;
import com.forgerock.openbanking.ssl.model.ForgeRockApplicationResponse;
import com.nimbusds.jose.jwk.JWK;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
    public static final String CURRENT = "CURRENT";
    public static final String CURRENT_SIGNING = "CURRENT_SIGNING";
    public static final String CURRENT_TRANSPORT = "CURRENT_TRANSPORT";
    public static final String CURRENT_ENCRYPTION = "CURRENT_ENCRYPTION";

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
    @Autowired
    private CryptoApiClient cryptoApiClient;

    @Override
    public ResponseEntity<List<Application>> getAllApplication() {
        return ResponseEntity.ok(applicationsRepository.findAll());
    }

    @Override
    public ResponseEntity read(@PathVariable String appId, Principal principal) {
        if (CURRENT.equals(appId)) {
            appId = principal.getName();
        }
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
            return ResponseEntity.ok(applicationsRepository.save(applicationService.createApplication(applicationRequest)));
        } finally {
            log.debug("Application created");
        }
    }

    @Override
    @RequestMapping(value = "/{applicationId}", method = RequestMethod.DELETE)
    public ResponseEntity delete(@PathVariable(value = "applicationId") String applicationId, Principal principal) {
        if (CURRENT.equals(applicationId)) {
            applicationId = principal.getName();
        }
        deleteApplication(applicationId);
        return ResponseEntity.ok().build();

    }

    @RequestMapping(value = "/{appId}/transport/jwk_uri", method = RequestMethod.GET)
    @Override
    public ResponseEntity transportKeysJwkUri(@PathVariable String appId, Principal principal) {
        if (CURRENT.equals(appId)) {
            appId = principal.getName();
        }
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        return ResponseEntity.ok(cryptoService.getTransportPublicJwks(isApplication.get()).toJSONObject().toJSONString());
    }

    @RequestMapping(value = "/{appId}/transport/rotate", method = RequestMethod.PUT)
    @Override
    public ResponseEntity transportKeysRotate(@PathVariable String appId, Principal principal) {
        if (CURRENT.equals(appId)) {
            appId = principal.getName();
        }
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
    public ResponseEntity transportKeysReset(@PathVariable String appId, Principal principal) {
        if (CURRENT.equals(appId)) {
            appId = principal.getName();
        }
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        Application application = isApplication.get();
        applicationService.resetTransportKeys(application);
        return ResponseEntity.ok(application);
    }

    @Override
    public ResponseEntity signingEncryptionKeysJwkUri(@PathVariable String appId, Principal principal) {
        if (CURRENT.equals(appId)) {
            appId = principal.getName();
        }
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Application '" + appId + "' can't be found.");
        }
        return ResponseEntity.ok(cryptoService.getPublicJwks(isApplication.get()).toJSONObject().toJSONString());
    }

    @RequestMapping(value = "/{appId}/rotate", method = RequestMethod.PUT)
    @Override
    public ResponseEntity signingEncryptionKeysRotate(@PathVariable String appId, Principal principal) {
        if (CURRENT.equals(appId)) {
            appId = principal.getName();
        }
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
    public ResponseEntity signingEncryptionKeysReset(@PathVariable String appId, Principal principal) {
        if (CURRENT.equals(appId)) {
            appId = principal.getName();
        }

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
    public ResponseEntity getKey(
            @PathVariable(name = "appId") String appId,
            @PathVariable(name = "keyId") String keyId,
            Principal principal) {
        if (CURRENT.equals(appId)) {
            appId = principal.getName();
        }
        try {
            return ResponseEntity.ok(cryptoApiClient.getKey(appId, keyId).toJSONString());
        } catch (IllegalArgumentException | ParseException e) {
            log.debug("Couldn't read key {} from app {}", keyId, appId, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }


    @RequestMapping(value = "/{appId}/key/{keyId}/certificate/public/", method = RequestMethod.PUT)
    @Override
    public ResponseEntity<String> getPublicCertificate(
            @PathVariable(name = "appId") String appId,
            @PathVariable(name = "keyId") String keyId,
            Principal principal) {
        if (CURRENT.equals(appId)) {
            appId = principal.getName();
        }
        try {
            return ResponseEntity.ok(cryptoApiClient.getPublicCert(appId, keyId));
        } catch (IllegalArgumentException e) {
            log.debug("Couldn't read key {} from app {}", keyId, appId, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @RequestMapping(value = "/{appId}/key/{keyId}/certificate/private/", method = RequestMethod.PUT)
    @Override
    public ResponseEntity<String> getPrivateCertificate(
            @PathVariable(name = "appId") String appId,
            @PathVariable(name = "keyId") String keyId,
            Principal principal) {

        if (CURRENT.equals(appId)) {
            appId = principal.getName();
        }
        try {
            return ResponseEntity.ok(cryptoApiClient.getPrivateCert(appId, keyId));
        } catch (IllegalArgumentException e) {
            log.debug("Couldn't read key {} from app {}", keyId, appId, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @Override
    @RequestMapping(value = "/current", method = RequestMethod.GET)
    public ResponseEntity getCurrentApplication(Principal principal) {
        Application application = applicationsRepository.findById(principal.getName()).get();

        ForgeRockApplicationResponse forgeRockApplicationResponse = new ForgeRockApplicationResponse();
        forgeRockApplicationResponse.setApplicationId(application.getIssuerId());
        forgeRockApplicationResponse.setTransportKey(application.getCurrentTransportKey().getJwk());

        return ResponseEntity.ok(forgeRockApplicationResponse);
    }

    private Application getApplication(Principal principal) {
        Application application;
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
            application = applicationsRepository.save(applicationService.createApplication(applicationRequest));

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
            application = applicationService.updateJWKMSApplicationFromForgeRockAppConfig(name, app.get(), application);
        }
        return application;
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
}
