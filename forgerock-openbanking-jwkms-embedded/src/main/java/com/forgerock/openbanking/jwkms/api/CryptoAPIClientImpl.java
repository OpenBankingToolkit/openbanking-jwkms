/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.openbanking.am.config.AMOpenBankingConfiguration;
import com.forgerock.openbanking.analytics.model.entries.JwtsGenerationEntry;
import com.forgerock.openbanking.analytics.services.MetricService;
import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.JwkMsKey;
import com.forgerock.openbanking.core.services.CryptoApiClientImpl;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.ForgeRockApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.SoftwareStatementRepository;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import com.forgerock.openbanking.jwkms.service.crypto.CryptoService;
import com.forgerock.openbanking.jwkms.service.keystore.JwkKeyStoreService;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import com.forgerock.openbanking.jwt.model.CreateDetachedJwtResponse;
import com.forgerock.openbanking.jwt.model.SigningRequest;
import com.forgerock.openbanking.jwt.model.ValidDetachedJwtResponse;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URL;
import java.security.Principal;
import java.text.ParseException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Primary
@Service
@Slf4j
public class CryptoAPIClientImpl implements CryptoApiClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoApiClientImpl.class);
    private Pattern jwsDetachedSignaturePattern = Pattern.compile("(.*\\.)(\\..*)");

    @Value("${jwkms.root}")
    private String jwkmsRoot;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private AMOpenBankingConfiguration amOpenBankingConfiguration;
    @Autowired
    private ObjectMapper objectMapper;
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
    private MetricService metricService;

    public static final String CURRENT_SIGNING = "CURRENT_SIGNING";
    public static final String CURRENT_TRANSPORT = "CURRENT_TRANSPORT";
    public static final String CURRENT_ENCRYPTION = "CURRENT_ENCRYPTION";
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    @Override
    public JWK getKey(String appId, String keyId) {
        Application application = getApplication(appId);
        keyId = getKeyId(application, keyId);
        return application.getKey(keyId).getJwk();
    }

    public String getPublicCert(String appId, String keyId) {
        Application application = getApplication(appId);
        keyId = getKeyId(application, keyId);

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
                return new String(bs.toByteArray());
            } else {
                throw new IllegalArgumentException("Key '" + keyId + "' can't be found.");
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

    public String getPrivateCert(String appId, String keyId) {
        Application application = getApplication(appId);
        keyId = getKeyId(application, keyId);

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
                return new String(bs.toByteArray());
            } else {
                throw new IllegalArgumentException("Key '" + keyId + "' can't be found.");
            }
        } catch (JOSEException e) {
            log.error("Couldn't not read keypair from JWK", e);
            throw new RuntimeException("Key '" + keyId + "' can't be loaded properly.");
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

    /**
     * Sign a set of claims
     * @param jwtClaimsSet
     * @return JWS serialized
     */
    @Override
    public String signClaims(SigningRequest signingRequest, JWTClaimsSet jwtClaimsSet)  {
        return signClaims(restTemplate, signingRequest, null, jwtClaimsSet);
    }
    /**
     * Sign a set of claims
     * @param jwtClaimsSet
     * @return JWS serialized
     */
    @Override
    public String signClaims(String issuerId, JWTClaimsSet jwtClaimsSet) {
        return signClaims(restTemplate, null, issuerId, jwtClaimsSet);
    }

    /**
     * Sign a set of claims
     * @param jwtClaimsSet
     * @return JWS serialized
     */
    @Override
    public String signClaims(SigningRequest signingRequest, String issuerId, JWTClaimsSet jwtClaimsSet) {
        return signClaims(restTemplate, signingRequest, issuerId, jwtClaimsSet);
    }
    /**
     * Sign a set of claims
     * @param jwtClaimsSet
     * @return JWS serialized
     */
    @Override
    public String signClaims(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, JWTClaimsSet jwtClaimsSet) {
        return signClaims(restTemplate, signingRequest, issuerId, jwtClaimsSet.toString(), "signClaims");
    }

    @Override
    public CreateDetachedJwtResponse signPayloadToDetachedJwt(SigningRequest signingRequest, String issuerId, String payload) {
        return signPayloadToDetachedJwt(restTemplate, signingRequest, issuerId, payload);
    }

    @Override
    public CreateDetachedJwtResponse signPayloadToDetachedJwt(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, String payload) {
        return signPayloadToDetachedJwt(restTemplate, signingRequest, issuerId, payload, "signPayloadToDetachedJwt");
    }


    private CreateDetachedJwtResponse signPayloadToDetachedJwt(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, String payload, String path)  {
        HttpHeaders headers = new HttpHeaders();
        if (issuerId != null) {
            headers.add("issuerId", issuerId);
        }
        if (signingRequest != null) {
            try {
                headers.add("signingRequest", objectMapper.writeValueAsString(signingRequest));
            } catch (JsonProcessingException e) {
                LOGGER.error("Can't serialise signing request '{}' into a string", signingRequest, e);
            }
        }
        HttpEntity<String> request = new HttpEntity<>(payload.toString(), headers);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sign claims {}", payload);
        }

        return restTemplate.postForObject(jwkmsRoot + "api/crypto/" + path, request, CreateDetachedJwtResponse.class);
    }

    private String signClaims(RestTemplate restTemplate, SigningRequest signingRequest, String issuerId, String payload, String path)  {
        String appId =  ((Principal) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getName();
        LOGGER.debug("Sign the claims {} for app {}", signingRequest, appId);
        Application application = getApplication(appId);

        try {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder(JWTClaimsSet.parse(payload)).build();
            //Metric
            metricService.addJwtsGenerationEntry(
                    JwtsGenerationEntry.builder()
                            .appId(application.getIssuerId())
                            .date(DateTime.now())
                            .jwtType(JwtsGenerationEntry.JwtType.JWS)
                            .build());

            return cryptoService.sign(issuerId, claimsSet, application, false).serialize();
        } catch (ParseException e) {
            LOGGER.error("Couldn't parse the claims received '{}'", payload, e);
            throw new RuntimeException("Couldn't parse the claims received: " + payload);
        }
    }
    /**
     * Sign and encrypt claims for an app not yet referenced in our system
     * @param jwtClaimsSet the claims
     * @param jwkUri the JWK uri of the external app
     * @return the JWE(JWS) serialized
     */
    @Override
    public String signAndEncryptClaims(JWTClaimsSet jwtClaimsSet, String jwkUri) throws JOSEException {
        return signAndEncryptClaims(null, jwtClaimsSet, jwkUri);
    }

    /**
     * Sign and encrypt claims for an app not yet referenced in our system
     * @param jwtClaimsSet the claims
     * @param jwkUri the JWK uri of the external app
     * @return the JWE(JWS) serialized
     */
    @Override
    public String signAndEncryptClaims(String issuerId, JWTClaimsSet jwtClaimsSet, String jwkUri) throws JOSEException {

            String appId = ((Principal) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getName();
            Application application = getApplication(appId);

            //Metric
            JwtsGenerationEntry jwtsGenerationEntry = new JwtsGenerationEntry();
            jwtsGenerationEntry.setAppId(application.getIssuerId());
            jwtsGenerationEntry.setDate(DateTime.now());
            jwtsGenerationEntry.setJwtType(JwtsGenerationEntry.JwtType.JWE_JWS);
            metricService.addJwtsGenerationEntry(jwtsGenerationEntry);

            return cryptoService.signAndEncrypt(issuerId, jwtClaimsSet,
                    getJwkForEncryption(jwkUri), application, false).serialize();

    }

    /**
     * Sign and encrypt claims for another app
     * @param jwtClaimsSet the claims
     * @param obAppId the app id for which the JWE is for.
     * @return the JWE(JWS) serialized
     */
    @Override
    public String signAndEncryptJwtForOBApp(JWTClaimsSet jwtClaimsSet, String obAppId) throws JOSEException {
        return signAndEncryptJwtForOBApp(null, jwtClaimsSet, obAppId);
    }

    /**
     * Sign and encrypt claims for another app
     * @param jwtClaimsSet the claims
     * @param obAppId the app id for which the JWE is for.
     * @return the JWE(JWS) serialized
     */
    @Override
    public String signAndEncryptJwtForOBApp(String issuerId, JWTClaimsSet jwtClaimsSet, String obAppId) throws JOSEException {

        String appId = ((Principal) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getName();

        Application applicationForIssuer = getApplication(appId);
        Application applicationForAudience = applicationForIssuer;

        //Metric
        JwtsGenerationEntry jwtsGenerationEntry = new JwtsGenerationEntry();
        jwtsGenerationEntry.setAppId(applicationForIssuer.getIssuerId());
        jwtsGenerationEntry.setDate(DateTime.now());
        jwtsGenerationEntry.setJwtType(JwtsGenerationEntry.JwtType.JWE_JWS);
        metricService.addJwtsGenerationEntry(jwtsGenerationEntry);

        return cryptoService.signAndEncrypt(issuerId, jwtClaimsSet,
                getJwkForEncryption(cryptoService.getPublicJwks(applicationForAudience)), applicationForIssuer, false)
                .serialize();
    }

    /**
     * Decrypt a JWE received for the current app
     * @param serializedJwe the jwe serialized
     * @return the JWS inside the JWE (the JWS is already validated)
     * @throws ParseException can't parse the JWE
     */
    @Override
    public SignedJWT decryptJwe(String serializedJwe) throws ParseException {
        return decryptJwe(null, serializedJwe);
    }

    /**
     * Decrypt a JWE received for the current app
     * @param serializedJwe the jwe serialized
     * @return the JWS inside the JWE (the JWS is already validated)
     * @throws ParseException can't parse the JWE
     */
    @Override
    public SignedJWT decryptJwe(String expectedAudienceId, String serializedJwe) throws ParseException {
        String appId = ((Principal) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getName();
        Application application = getApplication(appId);

        SignedJWT jws = cryptoService.decrypt((EncryptedJWT) JWTParser.parse(serializedJwe), application);
        return jws;
    }

    /**
     * Validate a JWS
     * @param serializedJws the jws serialized
     * @param expectedIssuerId the expected issuer ID
     * @throws InvalidTokenException the JWS is invalid
     */
    @Override
    public SignedJWT validateJws(String serializedJws, String expectedIssuerId) throws ParseException, InvalidTokenException {
        return validateJwsWithExpectedAudience(serializedJws, null, expectedIssuerId);
    }

    /**
     * Validate a JWS
     * @param serializedJws the jws serialized
     * @param expectedIssuerId the expected issuer ID
     * @throws InvalidTokenException the JWS is invalid
     */
    @Override
    public SignedJWT validateJwsWithExpectedAudience(String serializedJws, String expectedAudienceId, String expectedIssuerId) throws ParseException, InvalidTokenException {
        String appId = ((Principal) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getName();
        Application application = getApplication(appId);

        SignedJWT jws = (SignedJWT) JWTParser.parse(serializedJws);
        if (expectedIssuerId != null && !jws.getJWTClaimsSet().getIssuer().equals(expectedIssuerId)) {
            LOGGER.debug("JWS issuer id {} is not the one expected {}",
                    jws.getJWTClaimsSet().getIssuer(), expectedIssuerId);
            throw new InvalidTokenException("Invalid issuer");
        }
        cryptoService.validate(jws, expectedAudienceId, application);
        return jws;
    }

    /**
     * Validate a JWS
     * @param serializedJws the jws serialized
     * @param expectedIssuerId the expected issuer ID
     * @param jwkUri the issuer jwk URI
     * @throws InvalidTokenException the JWS is invalid
     */
    @Override
    public SignedJWT validateJws(String serializedJws, String expectedIssuerId, String jwkUri) throws InvalidTokenException, IOException, ParseException {
        return validateJws(serializedJws, null, expectedIssuerId, jwkUri);
    }


    @Override
    public SignedJWT validateJwsWithJWK(String serializedJws, String expectedIssuerId, String jwk) throws InvalidTokenException, ParseException {
        SignedJWT jws = (SignedJWT) JWTParser.parse(serializedJws);
        if (expectedIssuerId != null && !jws.getJWTClaimsSet().getIssuer().equals(expectedIssuerId)) {
            LOGGER.debug("JWS issuer id {} is not the one expected {}",
                    jws.getJWTClaimsSet().getIssuer(), expectedIssuerId);
            throw new InvalidTokenException("Invalid issuer");
        }
        cryptoService.validate(jws, expectedIssuerId, JWK.parse(jwk));
        return jws;
    }


    /**
     * Validate a JWS
     * @param serializedJws the jws serialized
     * @param expectedIssuerId the expected issuer ID
     * @param jwkUri the issuer jwk URI
     * @throws InvalidTokenException the JWS is invalid
     */
    @Override
    public SignedJWT validateJws(String serializedJws, String expectedAudienceId, String expectedIssuerId, String jwkUri)
            throws InvalidTokenException, ParseException, IOException {
        SignedJWT jws = (SignedJWT) JWTParser.parse(serializedJws);
        cryptoService.validate(jws, expectedIssuerId, jwkUri);
        return jws;
    }

    @Override
    public ValidDetachedJwtResponse validateDetachedJWS(String jwsDetachedSignature, Object body, String expectedAudienceId, String expectedIssuerId, String jwkUri)
            throws InvalidTokenException, ParseException, IOException {
        String jwsSerialized = rebuildJWS(jwsDetachedSignature, body.toString());
        LOGGER.debug("The JWS reconstruct from the detached signature: {}", jwsSerialized);
        SignedJWT jws = (SignedJWT) JWTParser.parse(jwsSerialized);
        return cryptoService.validateDetachedJwS(jws, expectedIssuerId, jwkUri);
    }

    @Override
    public ValidDetachedJwtResponse validateDetachedJWSWithJWK(String jwsDetachedSignature, Object body, String expectedAudienceId, String expectedIssuerId, JWK jwk)
            throws InvalidTokenException, ParseException, IOException {
        String jwsSerialized = rebuildJWS(jwsDetachedSignature, body.toString());

        SignedJWT jws = (SignedJWT) JWTParser.parse(jwsSerialized);
        return cryptoService.validateDetachedJwSWithJWK(jws, expectedIssuerId, jwk.toJSONString());
    }

    /**
     * Verify a stateless access token
     * @param accessTokenBearer an access token bearer or the JWT directly
     * @return the JWS
     * @throws ParseException can't parse the access token JWT, must not be a stateless JWT
     * @throws InvalidTokenException the access token is invalid
     */
    @Override
    public SignedJWT verifyAccessToken(String accessTokenBearer)
            throws ParseException, InvalidTokenException, IOException {
        accessTokenBearer = accessTokenBearer.replaceFirst("^Bearer ", "");
        SignedJWT signedAccessToken = (SignedJWT) JWTParser.parse(accessTokenBearer);
        validateJws(accessTokenBearer,null, amOpenBankingConfiguration.jwksUri);
        if (!amOpenBankingConfiguration.audiences.contains(signedAccessToken.getJWTClaimsSet().getIssuer())) {
            LOGGER.debug("Invalid audience {}, expecting {}", signedAccessToken.getJWTClaimsSet().getIssuer(), amOpenBankingConfiguration.audiences);
            throw new InvalidTokenException("Invalid audience '" + signedAccessToken.getJWTClaimsSet().getIssuer() + "', expecting '" +
                    amOpenBankingConfiguration.audiences + "'");
        }
        return signedAccessToken;
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

    private Application getApplication(String appId) {
        Optional<Application> isApplication = applicationsRepository.findById(appId);
        if (!isApplication.isPresent()) {
            throw new IllegalArgumentException("Application '" + appId + "' can't be found.");
        }
        return isApplication.get();
    }

    private String getKeyId(Application application, String keyId) {
        if (CURRENT_SIGNING.equals(keyId)) {
            return application.getCurrentSignKid();
        } else if (CURRENT_ENCRYPTION.equals(keyId)) {
            return application.getCurrentEncKid();
        } else if (CURRENT_TRANSPORT.equals(keyId)) {
            return application.getCurrentTransportKid();
        }
        return keyId;
    }


    private String rebuildJWS(String jwsDetachedSignature, String bodySerialised) {
        String jwtPayloadEncoded = new String(java.util.Base64.getEncoder().encode(bodySerialised.getBytes()));
        jwtPayloadEncoded = jwtPayloadEncoded.replace("=", "");
        Matcher jwsDetachedSignatureMatcher = jwsDetachedSignaturePattern.matcher(jwsDetachedSignature);
        if (!jwsDetachedSignatureMatcher.find()) {
            LOGGER.warn("{} is not a detached signature", jwsDetachedSignature);
            throw new IllegalArgumentException("'" + jwsDetachedSignature + "' is not a detached signature");
        }
        return jwsDetachedSignatureMatcher.group(1) + jwtPayloadEncoded + jwsDetachedSignatureMatcher.group(2);
    }
}
