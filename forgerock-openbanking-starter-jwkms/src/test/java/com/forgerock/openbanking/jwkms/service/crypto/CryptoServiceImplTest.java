/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.service.crypto;

import com.forgerock.openbanking.core.model.jwkms.Application;
import com.forgerock.openbanking.core.model.jwkms.JwkMsKey;
import com.forgerock.openbanking.core.rest.CreateDetachedJwtResponse;
import com.forgerock.openbanking.core.rest.ValidDetachedJwtResponse;
import com.forgerock.openbanking.core.token.TokenService;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import com.forgerock.openbanking.jwkms.service.jwkstore.JwkStoreService;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.forgerock.openbanking.jwkms.JwkTestHelper.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CryptoServiceImplTest {

    @Mock
    private JwkStoreService jwkStoreService;
    private TokenService tokenService = new TokenService();
    @Mock
    private ApplicationService applicationService;
    @Mock
    private ApplicationsRepository applicationsRepository;
    @Mock
    private JwkMsConfigurationProperties jwkMsConfigurationProperties;
    private CryptoServiceImpl cryptoService;


    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        cryptoService = new CryptoServiceImpl(jwkStoreService, tokenService, applicationService, applicationsRepository, jwkMsConfigurationProperties);
    }

    @Test
    public void getPublicJwks_nullApplication_returnEmptyKeys() {
        // When
        JWKSet publicJwks = cryptoService.getPublicJwks(null);

        // Then
        assertThat(publicJwks.getKeys()).isEmpty();
    }

    @Test
    public void getPublicJwks_noSignatureKeys_returnEncryptionKey() {
        // Given
        Application application = new Application();
        JwkMsKey validEncKey = mockJwkMsKey("validEncryption", KeyUse.ENCRYPTION, DateTime.now().minusDays(1), DateTime.now().plusDays(1));
        application.setCurrentEncKid(validEncKey.getKid());
        application.setKeys(ImmutableMap.of(validEncKey.getKid(), validEncKey));

        // When
        JWKSet publicJwks = cryptoService.getPublicJwks(application);

        // Then
        assertThat(publicJwks.getKeys()).containsExactly(validEncKey.getJwk());
    }

    @Test
    public void getPublicJwks_multipleKeys_returnEncryptionKeyAndValidSignatureKey() {
        // Given
        JwkMsKey validSignatureKey = mockJwkMsKey("validSignature", KeyUse.SIGNATURE, DateTime.now().minusDays(1), DateTime.now().plusDays(1));
        JwkMsKey validEncKey = mockJwkMsKey("validEncryption", KeyUse.ENCRYPTION, DateTime.now().minusDays(1), DateTime.now().plusDays(1));
        JwkMsKey notStartedSignatureKey = mockJwkMsKey("notStarted", KeyUse.SIGNATURE, DateTime.now().plusDays(1), DateTime.now().plusDays(2));
        JwkMsKey stoppedSignatureKey = mockJwkMsKey("stopped", KeyUse.SIGNATURE, DateTime.now().minusDays(2), DateTime.now().minusDays(1));

        Application application = new Application();
        application.setCurrentEncKid(validEncKey.getKid());
        application.setKeys(ImmutableMap.of(
                validSignatureKey.getKid(), validSignatureKey,
                validEncKey.getKid(), validEncKey,
                notStartedSignatureKey.getKid(), notStartedSignatureKey,
                stoppedSignatureKey.getKid(), stoppedSignatureKey
        ));

        // When
        JWKSet publicJwks = cryptoService.getPublicJwks(application);

        // Then
        assertThat(publicJwks.getKeys()).containsExactly(validEncKey.getJwk(), validSignatureKey.getJwk());
    }

    @Test
    public void getTransportPublicJwks_returnValidSignatureKey() {
        // Given
        JwkMsKey validSignatureKey = mockJwkMsKey("validSignature", KeyUse.SIGNATURE, DateTime.now().minusDays(1), DateTime.now().plusDays(1));
        JwkMsKey validEncKey = mockJwkMsKey("validEncryption", KeyUse.ENCRYPTION, DateTime.now().minusDays(1), DateTime.now().plusDays(1));
        JwkMsKey notStartedSignatureKey = mockJwkMsKey("notStarted", KeyUse.SIGNATURE, DateTime.now().plusDays(1), DateTime.now().plusDays(2));
        JwkMsKey stoppedSignatureKey = mockJwkMsKey("stopped", KeyUse.SIGNATURE, DateTime.now().minusDays(2), DateTime.now().minusDays(1));

        Application application = new Application();
        application.setTransportKeys(ImmutableMap.of(
                validSignatureKey.getKid(), validSignatureKey,
                validEncKey.getKid(), validEncKey,
                notStartedSignatureKey.getKid(), notStartedSignatureKey,
                stoppedSignatureKey.getKid(), stoppedSignatureKey
        ));

        // When
        JWKSet transportKeys = cryptoService.getTransportPublicJwks(application);

        // Then
        assertThat(transportKeys.getKeys()).containsExactly(validSignatureKey.getJwk());
    }

    @Test
    public void validate_jwtIsValid_issuedBySameApplication() throws Exception {
        // Given
        String issuerId = "5a6ca3f9-b42d-4aed-bd6b-c426e8ecaef4"; // Matches to one in encoded JWT
        String audienceId = "aud1";
        JwkMsKey encKey =  utf8FileToString
                .andThen(stringToJWK)
                .andThen(jwkToJwkMsKey)
                .apply("jwk/psEncryptionJwk.json");
        encKey.setValidityWindowStart(DateTime.now());
        JwkMsKey sigKey =  utf8FileToString
                .andThen(stringToJWK)
                .andThen(jwkToJwkMsKey)
                .apply("jwk/psSignatureJwk.json");
        sigKey.setValidityWindowStart(DateTime.now());

        Application application = new Application();
        application.setIssuerId(issuerId); // Same issuer as JWT
        application.setCurrentEncKid(encKey.getKid());
        application.setCurrentSignKid(sigKey.getKid());
        application.setKeys(ImmutableMap.of(sigKey.getKid(), sigKey, encKey.getKid(), encKey));

        SignedJWT jwt = cryptoService.sign(
                application.issuerId,
                new JWTClaimsSet.Builder().build(),
                application, false);

        when(applicationsRepository.findById(any())).thenReturn(Optional.of(application));

        // When
        cryptoService.validate(jwt, audienceId, application);

        // Then : validation succeed so no exception thrown
    }

    @Test
    public void validate_jwtIsValid_issuedByDifferentApplication() throws Exception {
        // Given
        String issuerId = "5a6ca3f9-b42d-4aed-bd6b-c426e8ecaef4"; // Matches to one in encoded JWT

        Application applicationFrom = new Application();
        applicationFrom.setIssuerId(issuerId);
        Application applicationTo = new Application();
        applicationTo.setIssuerId("differentAppIssuerId");

        JwkMsKey encKey =  utf8FileToString
                .andThen(stringToJWK)
                .andThen(jwkToJwkMsKey)
                .apply("jwk/psEncryptionJwk.json");
        encKey.setValidityWindowStart(DateTime.now());
        JwkMsKey sigKey =  utf8FileToString
                .andThen(stringToJWK)
                .andThen(jwkToJwkMsKey)
                .apply("jwk/psSignatureJwk.json");
        sigKey.setValidityWindowStart(DateTime.now());

        applicationFrom.setCurrentEncKid(encKey.getKid());
        applicationFrom.setCurrentSignKid(sigKey.getKid());
        applicationFrom.setKeys(ImmutableMap.of(sigKey.getKid(), sigKey, encKey.getKid(), encKey));

        SignedJWT jwt = cryptoService.sign(
                applicationFrom.issuerId,
                new JWTClaimsSet.Builder()
                        .audience(applicationTo.issuerId)
                        .build(),
                applicationFrom, false);

        applicationTo.setCurrentEncKid(encKey.getKid());
        applicationTo.setCurrentSignKid(sigKey.getKid());
        applicationTo.setKeys(ImmutableMap.of(sigKey.getKid(), sigKey, encKey.getKid(), encKey));

        when(applicationsRepository.findById(any())).thenReturn(Optional.of(applicationFrom));

        // When
        cryptoService.validate(jwt, applicationTo.issuerId, applicationTo);

        // Then : validation succeed so no exception thrown
    }

    @Test
    public void sign_getRSASignedJwt() {
        // Given
        JwkMsKey sigKey =  utf8FileToString
                .andThen(stringToJWK)
                .andThen(jwkToJwkMsKey)
                .apply("jwk/psSignatureJwk.json");
        Application application = new Application();
        application.setCurrentSignKid(sigKey.getKid());
        application.setKeys(ImmutableMap.of(sigKey.getKid(), sigKey));

        // When
        SignedJWT signedJwt = cryptoService.sign(
                "5a6ca3f9-b42d-4aed-bd6b-c426e8ecaef4",
                new JWTClaimsSet.Builder().build(),
                application, false);

        // Then
        assertThat(signedJwt).isNotNull();
        assertThat(signedJwt.getState()).isEqualTo(JWSObject.State.SIGNED);
        assertThat(signedJwt.getHeader().toJSONObject().toJSONString()).isEqualTo("{\"kid\":\"159e5a7ed77ec6fe3db14f0d6e3d4585902c0192\",\"alg\":\"PS256\"}");
        assertThat(signedJwt.getHeader().getKeyID()).isEqualTo(sigKey.getKid());
        assertThat(signedJwt.getHeader().getAlgorithm().getName()).isEqualTo(sigKey.getAlgorithm().getName());
    }

    @Test
    public void signThenEncrypt_getRSAEncryptedJwt() throws Exception {
        // Given
        JwkMsKey sigKey = utf8FileToString
                .andThen(stringToJWK)
                .andThen(jwkToJwkMsKey)
                .apply("jwk/psSignatureJwk.json");

        Application application = new Application();
        application.setCurrentSignKid(sigKey.getKid());
        application.setKeys(ImmutableMap.of(sigKey.getKid(), sigKey));

        JWK encKey = utf8FileToString
                .andThen(stringToJWK)
                .apply("jwk/psEncryptionJwk.json");

        // When
        EncryptedJWT encryptedJwt = cryptoService.signAndEncrypt(
                "5a6ca3f9-b42d-4aed-bd6b-c426e8ecaef4",
                new JWTClaimsSet.Builder().build(),
                (RSAKey) encKey,
                application, false);

        // Then
        assertThat(encryptedJwt).isNotNull();
        assertThat(encryptedJwt.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
        assertThat(encryptedJwt.getHeader().getKeyID()).isEqualTo(encKey.getKeyID());
        assertThat(encryptedJwt.getHeader().getEncryptionMethod().toString()).isEqualTo("A128CBC-HS256");
        assertThat(encryptedJwt.getHeader().getAlgorithm().getName()).isEqualTo(encKey.getAlgorithm().getName());
    }

    @Test
    public void signDetachedJwt() throws JOSEException, ParseException, UnsupportedEncodingException {
        // Given
        JwkMsKey sigKey =  utf8FileToString
                .andThen(stringToJWK)
                .andThen(jwkToJwkMsKey)
                .apply("jwk/psSignatureJwk.json");
        Application application = new Application();
        application.setCurrentSignKid(sigKey.getKid());
        application.setKeys(ImmutableMap.of(sigKey.getKid(), sigKey));
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("foo", "bar")
                .build();

        // When
        CreateDetachedJwtResponse detachedJwtResponse = cryptoService.signPayloadToDetachedJwt(
                null,
                null,
                claims.toString(),
                application);
        SignedJWT detachedJwt = SignedJWT.parse(detachedJwtResponse.detachedSignature);

        // Then
        assertThat(detachedJwt).isNotNull();
        JWSVerifier verifier = new RSASSAVerifier(((RSAKey)sigKey.getJwk()).toRSAPublicKey(), new HashSet<>(
                ImmutableList.of("b64", "http://openbanking.org.uk/iss", "http://openbanking.org.uk/iat")));

        byte[] payloadBytes = claims.toString().getBytes("UTF-8");
        byte[] headerBytes = (detachedJwt.getHeader().toBase64URL().toString() + '.').getBytes("UTF-8");
        byte[] signingInput = new byte[headerBytes.length + payloadBytes.length];
        System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
        System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length, payloadBytes.length);

        assertThat(verifier.verify(detachedJwt.getHeader(), signingInput, detachedJwt.getSignature())).isTrue();
    }

    @Test
    public void verifyDetachedJwt() throws ParseException {
        // Given
        JwkMsKey sigKey =  utf8FileToString
                .andThen(stringToJWK)
                .andThen(jwkToJwkMsKey)
                .apply("jwk/psSignatureJwk.json");
        Application application = new Application();
        application.setCurrentSignKid(sigKey.getKid());
        application.setKeys(ImmutableMap.of(sigKey.getKid(), sigKey));
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("foo", "bar")
                .build();
        CreateDetachedJwtResponse detachedJwtResponse = cryptoService.signPayloadToDetachedJwt(
                null,
                null,
                claims.toString(),
                application);
        SignedJWT detachedJwt = SignedJWT.parse(rebuildJWS(detachedJwtResponse.detachedSignature, claims.toString()));

        // When
        ValidDetachedJwtResponse validDetachedJwtResponse = cryptoService.validateDetachedJwSWithJWK(
                detachedJwt, null, sigKey.getJwkSerialized());

        // Then
        assertThat(validDetachedJwtResponse).isNotNull();
        assertThat(validDetachedJwtResponse.isValid).isTrue();
    }

    private String rebuildJWS(String jwsDetachedSignature, String bodySerialised) {
        Pattern jwsDetachedSignaturePattern = Pattern.compile("(.*\\.)(\\..*)");

        String jwtPayloadEncoded = new String(Base64.getEncoder().encode(bodySerialised.getBytes()));
        jwtPayloadEncoded = jwtPayloadEncoded.replace("=", "");
        Matcher jwsDetachedSignatureMatcher = jwsDetachedSignaturePattern.matcher(jwsDetachedSignature);
        if (!jwsDetachedSignatureMatcher.find()) {
            throw new IllegalArgumentException("'" + jwsDetachedSignature + "' is not a detached signature");
        }
        return jwsDetachedSignatureMatcher.group(1) + jwtPayloadEncoded + jwsDetachedSignatureMatcher.group(2);
    }

    // Helper
    private static JwkMsKey mockJwkMsKey(String id, KeyUse keyUse, DateTime validityWindowStart, DateTime validityWindowStop) {
        JwkMsKey key = mock(JwkMsKey.class);

        JWK jwk = mock(JWK.class);
        when(jwk.getKeyUse()).thenReturn(keyUse);

        when(key.getKid()).thenReturn(id);
        when(key.getJwk()).thenReturn(jwk);
        when(key.getValidityWindowStart()).thenReturn(validityWindowStart);
        when(key.getValidityWindowStop()).thenReturn(validityWindowStop);
        return key;
    }


}