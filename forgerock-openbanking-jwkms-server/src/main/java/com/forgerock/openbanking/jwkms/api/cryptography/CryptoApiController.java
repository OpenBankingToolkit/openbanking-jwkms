/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.api.cryptography;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.analytics.model.entries.JwtsGenerationEntry;
import com.forgerock.openbanking.analytics.model.entries.JwtsValidationEntry;
import com.forgerock.openbanking.analytics.services.MetricService;
import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.ValidJwtResponse;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import com.forgerock.openbanking.jwkms.service.crypto.CryptoService;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import com.forgerock.openbanking.jwt.model.SigningRequest;
import com.forgerock.openbanking.jwt.model.ValidDetachedJwtResponse;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.net.URL;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Controller
public class CryptoApiController implements CryptoApi {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoApiController.class);

    @Autowired
    private CryptoService cryptoService;
    @Autowired
    private ApplicationsRepository applicationsRepository;
    @Autowired
    private ApplicationService applicationService;
    @Autowired
    private MetricService metricService;
    @Autowired
    private ObjectMapper mapper;
    @Autowired
    private CryptoApiClient cryptoApiClient;

    private Pattern jwsDetachedSignaturePattern = Pattern.compile("(.*\\.)(\\..*)");

    @Override
    public ResponseEntity<String> signClaims(
            @RequestHeader(value = "issuerId", required = false) String issuerId,
            @RequestHeader(value = "includeKey", defaultValue = "false", required = false) boolean includeKey,
            @RequestBody String claimsSetJsonSerialised,
            Principal principal) {
        LOGGER.debug("Sign the claims {} for app {}", claimsSetJsonSerialised, principal.getName());


        try {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder(JWTClaimsSet.parse(claimsSetJsonSerialised)).build();
            return ResponseEntity.ok(cryptoApiClient.signClaims(issuerId, claimsSet, includeKey));
        } catch (ParseException e) {
            LOGGER.error("Couldn't parse the claims received '{}'", claimsSetJsonSerialised, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the claims received: " + claimsSetJsonSerialised);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Application '{}' doesn't exist", principal.getName(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not found application '"
                            + principal.getName() +"'");
        }
    }

    @Override
    public ResponseEntity signPayloadToDetachedJwt(
            @RequestHeader(value = "issuerId", required = false) String issuerId,
            @RequestHeader(value = "signingRequest", required = false) String signingRequestSerialised,
            @RequestBody String payload,
            Principal principal) {
        SigningRequest signingRequest;
        try {
            signingRequest = deserialisedSigningRequest(signingRequestSerialised);
        } catch (IOException e) {
            LOGGER.error("Couldn't parse the signing request '{}'", signingRequestSerialised, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the signing request: " + signingRequestSerialised);
        }

        try {
            Application application = applicationsRepository.findById(principal.getName()).get();
            //Metric
            JwtsGenerationEntry jwtsGenerationEntry = new JwtsGenerationEntry();
            jwtsGenerationEntry.setAppId(application.getIssuerId());
            jwtsGenerationEntry.setDate(DateTime.now());
            jwtsGenerationEntry.setJwtType(JwtsGenerationEntry.JwtType.JWS);
            metricService.addJwtsGenerationEntry(jwtsGenerationEntry);

            return ResponseEntity.ok(cryptoService.signPayloadToDetachedJwt(signingRequest, issuerId, payload, application));
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Application '{}' doesn't exist", principal.getName(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not found application '"
                    + principal.getName() +"'");
        }
    }

    @Override
    public ResponseEntity<String> signAndEncryptJwt(
            @RequestHeader(value = "issuerId", required = false) String issuerId,
            @RequestHeader(value = "jwkUri") String jwkUri,
            @RequestBody String claimsSetJsonSerialised,
            Principal principal) {
        LOGGER.debug("Sign the claims {} and encrypt it with jwk uri {} for app {}",
                claimsSetJsonSerialised, jwkUri, principal.getName());
        //Metric
        JwtsValidationEntry jwtsValidationEntry = new JwtsValidationEntry();
        jwtsValidationEntry.setDate(DateTime.now());

        try {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder(JWTClaimsSet.parse(claimsSetJsonSerialised)).build();
            return ResponseEntity.ok(cryptoApiClient.signAndEncryptClaims(issuerId, claimsSet, jwkUri));
        } catch (JOSEException | ParseException e) {
            LOGGER.error("Couldn't parse the claims received '{}'", claimsSetJsonSerialised, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the claims received: " + claimsSetJsonSerialised);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Application '{}' doesn't exist", principal.getName(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not found application '"
                    + principal.getName() +"'");
        }
    }

    @Override
    public ResponseEntity<String> signAndEncryptJwtForOBApp(
            @RequestHeader(value = "issuerId", required = false) String issuerId,
            @RequestHeader(value = "obAppId") String obAppId,
            @RequestHeader(value = "includeKey", defaultValue = "false", required = false) boolean includeKey,
            @RequestBody String claimsSetJsonSerialised,
            Principal principal) {
        LOGGER.debug("Sign the claims {} and encrypt it for the app {} by the app {}",
                claimsSetJsonSerialised, obAppId, principal.getName());
        //Metric
        JwtsValidationEntry jwtsValidationEntry = new JwtsValidationEntry();
        jwtsValidationEntry.setDate(DateTime.now());

        try {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder(JWTClaimsSet.parse(claimsSetJsonSerialised))
                    .build();
            return ResponseEntity.ok(cryptoApiClient.signAndEncryptJwtForOBApp(issuerId, claimsSet, principal.getName()));
        } catch (JOSEException | ParseException e) {
            LOGGER.error("Couldn't parse the claims received '{}'", claimsSetJsonSerialised, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the claims received: " + claimsSetJsonSerialised);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Application '{}' doesn't exist", principal.getName(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not found application '"
                    + principal.getName() +"'");
        }
    }

    @Override
    public ResponseEntity<String> decryptJwe(
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestBody String jweSerialized,
            Principal principal) {

        LOGGER.debug("decrypt jwe {} by the app {}", jweSerialized, principal.getName());
        //Metric
        JwtsValidationEntry jwtsValidationEntry = new JwtsValidationEntry();
        jwtsValidationEntry.setDate(DateTime.now());
        try {
            return ResponseEntity.ok(cryptoApiClient.decryptJwe(expectedAudienceId, jweSerialized).serialize());
        } catch (JOSEException | ParseException e) {
            LOGGER.error("Couldn't parse jwe received '{}'", jweSerialized, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the jwe received");
        } catch (IllegalArgumentException e) {
            LOGGER.warn("", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not found application '"
                    + principal.getName() +"'");
        }
    }

    @Override
    public ResponseEntity validateJwsWithJWK(
            @RequestHeader(value = "expectedIssuerId", required = false) String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestHeader(value = "jwk", required = false) String jwk,
            @RequestBody String jwsSerialized,
            Principal principal) {
        //Metric
        JwtsValidationEntry jwtsValidationEntry = new JwtsValidationEntry();
        jwtsValidationEntry.setDate(DateTime.now());

        try {
            SignedJWT jws = (SignedJWT) JWTParser.parse(jwsSerialized);
            if (expectedIssuerId != null && !jws.getJWTClaimsSet().getIssuer().equals(expectedIssuerId)) {
                LOGGER.debug("JWS issuer id {} is not the one expected {}",
                        jws.getJWTClaimsSet().getIssuer(), expectedIssuerId);
                return ResponseEntity.status(HttpStatus.OK).body("Invalid issuer");
            }
            cryptoService.validate(jws, expectedAudienceId, JWK.parse(jwk));

            //Metric
            jwtsValidationEntry.setWasValid(true);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);

            return ResponseEntity.ok().body(ValidJwtResponse.valid(jws));
        } catch (ParseException e) {
            LOGGER.error("Couldn't parse jws received '{}'", jwsSerialized, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the jws received");
        } catch (InvalidTokenException | IllegalArgumentException e) {
            //Metric
            jwtsValidationEntry.setWasValid(false);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);
            return ResponseEntity.status(HttpStatus.OK).body(
                    ValidJwtResponse.invalid(e.getMessage()));
        }
    }

    @Override
    public ResponseEntity validateJws(
            @RequestHeader(value = "expectedIssuerId", required = false) String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestBody String jwsSerialized,
            Principal principal) {
        LOGGER.debug("Validate jwe {} expected issuer id {} by the app {}",
                jwsSerialized, expectedIssuerId, principal.getName());

        Application application;
        try {
            application = applicationsRepository.findById(principal.getName()).get();
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Application '" + principal.getName() +"' doesn't exist");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not found application '"
                    + principal.getName() + "'");
        }
        //Metric
        JwtsValidationEntry jwtsValidationEntry = new JwtsValidationEntry();
        jwtsValidationEntry.setAppId(application.getIssuerId());
        jwtsValidationEntry.setDate(DateTime.now());

        try {
            SignedJWT jws = cryptoApiClient.validateJwsWithExpectedAudience(jwsSerialized, expectedAudienceId, expectedIssuerId);
            //Metric
            jwtsValidationEntry.setWasValid(true);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);
            return ResponseEntity.ok().body(ValidJwtResponse.valid(jws));
        } catch (ParseException e) {
            LOGGER.error("Couldn't parse jws received '{}'", jwsSerialized, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the jws received");
        } catch (InvalidTokenException | IllegalArgumentException e) {
            //Metric
            jwtsValidationEntry.setWasValid(false);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);
            return ResponseEntity.status(HttpStatus.OK).body(
                    ValidJwtResponse.invalid(e.getMessage()));
        }
    }

    @Override
    public ResponseEntity validateJws(
            @RequestHeader(value = "expectedIssuerId", required = false) String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestHeader(value = "jwkUri") String jwkUri,
            @RequestBody String jwsSerialized,
            Principal principal) {
        LOGGER.debug("Validate jws {} expected issuer id {} by the app {}",
                jwsSerialized, expectedIssuerId, principal.getName());

        //Metric
        JwtsValidationEntry jwtsValidationEntry = new JwtsValidationEntry();
        jwtsValidationEntry.setDate(DateTime.now());
        try {

            SignedJWT jws = cryptoApiClient.validateJws(jwsSerialized, expectedAudienceId, expectedIssuerId, jwkUri);

            //Metric
            jwtsValidationEntry.setWasValid(true);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);

            return ResponseEntity.ok().body(ValidJwtResponse.valid(jws));
        } catch ( IOException e) {
            LOGGER.error("Connection issue to '{}'", jwkUri, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Connection issue to '" + jwkUri + "'");
        } catch (ParseException e) {
            LOGGER.error("Couldn't parse jws received '{}'", jwsSerialized, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the jws received");
        } catch (InvalidTokenException | IllegalArgumentException e) {
            //Metric
            jwtsValidationEntry.setWasValid(false);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);
            return ResponseEntity.status(HttpStatus.OK).body(
                    ValidJwtResponse.invalid(e.getMessage()));
        }
    }

    @Override
    public ResponseEntity validateDetachedJWSWithJwkUri(
            @RequestHeader(value = "expectedIssuerId", required = false) String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestHeader(value = "jwkUri") String jwkUri,
            @RequestHeader(value = "x-jws-signature") String jwsDetachedSignature,
            @RequestBody String bodySerialised,
            Principal principal) {
        LOGGER.debug("Validate detached JWS {} with body {} expected issuer id {} by the app {}",
                jwsDetachedSignature, bodySerialised, expectedIssuerId, principal.getName());

        //Metric
        JwtsValidationEntry jwtsValidationEntry = new JwtsValidationEntry();
        jwtsValidationEntry.setDate(DateTime.now());

        try {
            ValidDetachedJwtResponse validDetachedJwtResponse = cryptoApiClient.validateDetachedJWS(jwsDetachedSignature, bodySerialised, expectedAudienceId, expectedIssuerId, jwkUri);

            //Metric
            jwtsValidationEntry.setWasValid(validDetachedJwtResponse.isValid);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);

            return ResponseEntity.ok().body(validDetachedJwtResponse);
        } catch ( IOException e) {
            LOGGER.error("Connection issue to '{}'", jwkUri, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Connection issue to '" + jwkUri + "'");
        } catch (ParseException e) {
            LOGGER.error("Couldn't parse rebuild jws", e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the jws received");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.OK).body(
                    ValidJwtResponse.invalid(e.getMessage()));
        } catch (InvalidTokenException e) {
            //Metric
            jwtsValidationEntry.setWasValid(false);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);
            return ResponseEntity.status(HttpStatus.OK).body(
                    ValidDetachedJwtResponse.invalid(e.getMessage()));
        }
    }

    @Override
    public ResponseEntity validateDetachedJWS(
            @RequestHeader(value = "expectedIssuerId", required = false) String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestHeader(value = "x-jws-signature") String jwsDetachedSignature,
            @RequestBody String bodySerialised,
            Principal principal) {
        LOGGER.debug("Validate detached JWS {} with body {} expected issuer id {} by the app {}",
                jwsDetachedSignature, bodySerialised, expectedIssuerId, principal.getName());
        //Metric
        JwtsValidationEntry jwtsValidationEntry = new JwtsValidationEntry();
        jwtsValidationEntry.setDate(DateTime.now());

        String jwsSerialized = rebuildJWS(jwsDetachedSignature, bodySerialised);
        try {
            SignedJWT jws = (SignedJWT) JWTParser.parse(jwsSerialized);
            ValidDetachedJwtResponse validDetachedJwtResponse = cryptoService.validateDetachedJwS(jws, expectedIssuerId);

            //Metric
            jwtsValidationEntry.setWasValid(validDetachedJwtResponse.isValid);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);

            return ResponseEntity.ok().body(validDetachedJwtResponse);
        } catch (ParseException e) {
            LOGGER.error("Couldn't parse jws received '{}'", jwsSerialized, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the jws received");
        }
    }

    @Override
    public ResponseEntity validateDetachedJWSWithJWK(
            @RequestHeader(value = "expectedIssuerId", required = false) String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestHeader(value = "x-jws-signature") String jwsDetachedSignature,
            @RequestHeader(value = "jwk", required = false) String jwk,
            @RequestBody String bodySerialised,
            Principal principal) {
        LOGGER.debug("Validate detached JWS {} with body {} expected issuer id {} by the app {}",
                jwsDetachedSignature, bodySerialised, expectedIssuerId, principal.getName());
        //Metric
        JwtsValidationEntry jwtsValidationEntry = new JwtsValidationEntry();
        jwtsValidationEntry.setDate(DateTime.now());

        String jwsSerialized = rebuildJWS(jwsDetachedSignature, bodySerialised);
        try {
            SignedJWT jws = (SignedJWT) JWTParser.parse(jwsSerialized);
            ValidDetachedJwtResponse validDetachedJwtResponse = cryptoService.validateDetachedJwSWithJWK(jws, expectedIssuerId, jwk);

            cryptoApiClient.validateDetachedJWSWithJWK(jwsDetachedSignature, bodySerialised, expectedAudienceId, expectedIssuerId, JWK.parse(jwk));
            //Metric
            jwtsValidationEntry.setWasValid(validDetachedJwtResponse.isValid);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);

            return ResponseEntity.ok().body(validDetachedJwtResponse);
        } catch (ParseException | IOException e) {
            LOGGER.error("Couldn't parse jws received '{}'", jwsSerialized, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Couldn't parse the jws received");
        } catch (InvalidTokenException e) {
            //Metric
            jwtsValidationEntry.setWasValid(false);
            metricService.addJwtsValidationEntry(jwtsValidationEntry);
            return ResponseEntity.status(HttpStatus.OK).body(
                    ValidDetachedJwtResponse.invalid(e.getMessage()));
        }
    }

    @Override
    public ResponseEntity rotateSigningAndEncryptionKeys(Principal principal) {
        LOGGER.debug("Rotate keys for {}", principal.getName());
        Application application = applicationsRepository.findById(principal.getName()).get();
        applicationService.rotateKeys(application);
        return ResponseEntity.ok(application);
    }

    @Override
    public ResponseEntity resetSigningAndEncryptionKeys(Principal principal) {
        LOGGER.debug("Reset keys for {}", principal.getName());
        Application application = applicationsRepository.findById(principal.getName()).get();
        applicationService.resetKeys(application);
        return ResponseEntity.ok(application);
    }

    @Override
    public ResponseEntity rotateTransportKeys(Principal principal) {
        LOGGER.debug("Rotate keys for {}", principal.getName());
        Application application = applicationsRepository.findById(principal.getName()).get();
        applicationService.rotateTransportKeys(application);
        return ResponseEntity.ok(application);
    }

    @Override
    public ResponseEntity resetTransportKeys(Principal principal) {
        LOGGER.debug("Reset keys for {}", principal.getName());
        Application application = applicationsRepository.findById(principal.getName()).get();
        applicationService.resetTransportKeys(application);
        return ResponseEntity.ok(application);
    }

    @Override
    public ResponseEntity generateCSR(
            @RequestParam(value = "keyUse") KeyUse keyUse,
            @RequestParam(value = "certificateConfiguration") CertificateConfiguration certificateConfiguration,
            Principal principal
    ) {
        LOGGER.debug("Generate CSR for {}", principal.getName());
        try {
            Application application = applicationsRepository.findById(principal.getName()).get();
            return ResponseEntity.ok().body(applicationService.generateCSR(application,keyUse,certificateConfiguration));
        } catch (CertificateException e) {
            LOGGER.error("Couldn't generate CSR for key use {} and for app id", keyUse, principal.getName());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @Override
    public ResponseEntity importCSRResponse(
            @RequestHeader(value = "kid") String kid,
            @RequestHeader(value = "keyUse") KeyUse keyUse,
            @RequestHeader(value = "alias") String alias,
            @RequestBody String pem,
            Principal principal
    ) {
        LOGGER.debug("Import CSR response for key {} : pem {}", kid, pem, principal.getName());
        try {
            Application application = applicationsRepository.findById(principal.getName()).get();
            applicationService.importCSRResponse(application, alias, kid, keyUse,  pem);
            return ResponseEntity.ok().build();
        } catch (CertificateException e) {
            LOGGER.error("Couldn't import pem for key use {}, alias {}, kid {} and for app id", keyUse, alias, kid, principal.getName());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @Override
    public  ResponseEntity readApplication(
            Principal principal) {
        LOGGER.debug("Read application for {}", principal.getName());
        Application application = applicationsRepository.findById(principal.getName()).get();
        return ResponseEntity.ok(application);
    }

    private RSAKey getJwkForEncryption(String jwkUri) {
        return getJwkForEncryption(getJwkSet(jwkUri));
    }

    private RSAKey getJwkForEncryption(JWKSet jwkSet) {
        for (JWK jwk : jwkSet.getKeys()) {
            if (jwk.getKeyUse() == KeyUse.ENCRYPTION
                    && jwk instanceof RSAKey) {
                return (RSAKey) jwk;
            }
        }
        return null;
    }

    private synchronized JWKSet getJwkSet(String jwkUri) {
        LOGGER.debug("Get jwk uri {}", jwkUri);
        try {
            return JWKSet.load(new URL(jwkUri));
        } catch (IOException e) {
            LOGGER.error("Can't connect to jwk uri {}", jwkUri, e);
            throw new RuntimeException("Can't connect to " + jwkUri, e);
        } catch (ParseException e) {
            LOGGER.error("Can't parse content of jwk uri {}", jwkUri, e);
            throw new RuntimeException("Can't parse " + jwkUri, e);
        }
    }

    private SigningRequest deserialisedSigningRequest(String signingRequestSerialised) throws IOException {
        if (signingRequestSerialised != null) {
            return mapper.readValue(signingRequestSerialised, SigningRequest.class);
        }
        return null;
    }


    private String rebuildJWS(String jwsDetachedSignature, String bodySerialised) {
        String jwtPayloadEncoded = new String(Base64.getEncoder().encode(bodySerialised.getBytes()));
        jwtPayloadEncoded = jwtPayloadEncoded.replace("=", "");
        Matcher jwsDetachedSignatureMatcher = jwsDetachedSignaturePattern.matcher(jwsDetachedSignature);
        if (!jwsDetachedSignatureMatcher.find()) {
            LOGGER.warn("{} is not a detached signature", jwsDetachedSignature);
            throw new IllegalArgumentException("'" + jwsDetachedSignature + "' is not a detached signature");
        }
        return jwsDetachedSignatureMatcher.group(1) + jwtPayloadEncoded + jwsDetachedSignatureMatcher.group(2);
    }
}
