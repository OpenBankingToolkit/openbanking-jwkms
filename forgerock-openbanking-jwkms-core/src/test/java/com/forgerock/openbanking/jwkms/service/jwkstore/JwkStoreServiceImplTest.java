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
package com.forgerock.openbanking.jwkms.service.jwkstore;

import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.core.model.JwkMsKey;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.service.keystore.JwkKeyStoreService;
import com.forgerock.openbanking.ssl.model.csr.CSRGenerationResponse;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;


@RunWith(MockitoJUnitRunner.class)
public class JwkStoreServiceImplTest {

    @Mock
    private JwkKeyStoreService mockKeyStoreService;

    @Mock
    private JwkMsConfigurationProperties jwkMsConfigurationProperties;

    // Class under test
    private JwkStoreServiceImpl jwkStoreServiceImpl;

    @Mock
    private KeyStoreSpi keyStoreSpiMock;

    // See setUp()
    private KeyStore keyStoreMock;

    private String KEYSTORE_PASSWORD = "pass";

    @Before
    public void setUp() throws Exception {
        jwkStoreServiceImpl = new JwkStoreServiceImpl(mockKeyStoreService, jwkMsConfigurationProperties);

        // This unusual way of mocking is required to mock java system Key Store
        keyStoreMock = new KeyStore(keyStoreSpiMock, null, "test"){ };
        keyStoreMock.load(null);
        when(mockKeyStoreService.getKeyStore()).thenReturn(keyStoreMock);
        when(jwkMsConfigurationProperties.getJwkKeyStorePassword()).thenReturn(KEYSTORE_PASSWORD);
    }

    @Test
    public void getKey_returnValidKeyPair() throws Exception {
        // Given
        String keyAlias = "myAlias";
        PublicKey publicKey = mock(PublicKey.class);
        PrivateKey privateKey = mock(PrivateKey.class);
        Certificate cert = mock(Certificate.class);

        // This unusual way of mocking is required to mock java system Key Store
        when(keyStoreSpiMock.engineGetKey(eq(keyAlias), any())).thenReturn(privateKey);
        when(keyStoreSpiMock.engineGetCertificate(keyAlias)).thenReturn(cert);
        when(cert.getPublicKey()).thenReturn(publicKey);

        // When
        KeyPair keyPair = jwkStoreServiceImpl.getKey(keyAlias);

        // Then
        assertThat(keyPair.getPublic()).isEqualTo(publicKey);
        assertThat(keyPair.getPrivate()).isEqualTo(privateKey);
    }

    @Test
    public void getKey_keyNotFound() throws Exception {
        // Given

        // This unusual way of mocking is required to mock java system Key Store
        KeyStoreSpi keyStoreSpiMock = mock(KeyStoreSpi.class);
        KeyStore keyStoreMock = new KeyStore(keyStoreSpiMock, null, "test"){ };
        keyStoreMock.load(null);
        when(keyStoreSpiMock.engineGetKey(any(), any())).thenReturn(null);

        when(mockKeyStoreService.getKeyStore()).thenReturn(keyStoreMock);
        when(jwkMsConfigurationProperties.getJwkKeyStorePassword()).thenReturn("pass");

        // When
        KeyPair keyPair = jwkStoreServiceImpl.getKey("notSuch");

        // Then
        assertThat(keyPair).isNull();
    }

    @Test
    public void generateRSAKeyPair() {
        // When
        KeyPair keyPair = jwkStoreServiceImpl.generateKeyPair("myAlias", null, JWSAlgorithm.RS256, null);

        // Then
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
        assertThat(keyPair.getPrivate()).isNotNull();
        assertThat(keyPair.getPrivate().getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    public void generateECKeyPair() {
        // When
        KeyPair keyPair = jwkStoreServiceImpl.generateKeyPair("myAlias", new CertificateConfiguration(), JWSAlgorithm.ES256, Curve.P_256.toECParameterSpec());

        // Then
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("ECDSA");
        assertThat(keyPair.getPrivate()).isNotNull();
        assertThat(keyPair.getPrivate().getAlgorithm()).isEqualTo("ECDSA");
    }

    @Test
    public void generateKeyPair_unknownAlgorithm() {
        assertThatThrownBy(
                // When
                () -> jwkStoreServiceImpl.generateKeyPair("myAlias", null, Algorithm.NONE, null))
                // Then
                .isExactlyInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void getPrivateJWK() throws Exception {
        // Given
        JwkMsKey mockJwkMsKey = mock(JwkMsKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        when(privateKey.getPrivateExponent()).thenReturn(new BigInteger("34832987"));

        when(jwkMsConfigurationProperties.getCertificateAuthorityAlias()).thenReturn("caAlias");
        when(keyStoreSpiMock.engineGetCertificate("caAlias")).thenReturn(getTestCertificate());

        when(mockJwkMsKey.getKeystoreAlias()).thenReturn("myAlias");
        when(mockJwkMsKey.getAlgorithm()).thenReturn(JWSAlgorithm.RS512);
        when(mockJwkMsKey.getKid()).thenReturn("123");
        when(mockJwkMsKey.getKeyUse()).thenReturn(KeyUse.SIGNATURE);
        when(keyStoreSpiMock.engineGetCertificate("myAlias")).thenReturn(getTestCertificate());
        when(keyStoreSpiMock.engineGetKey(eq("myAlias"), any())).thenReturn(privateKey);

        // When
        JWK privateJwk = jwkStoreServiceImpl.getPrivateJWK(mockJwkMsKey);

        // Then
        assertThat(privateJwk).isNotNull();
    }


    @Test
    public void getCertificate() throws Exception {
        // Given
        String keyAlias = "myAlias";
        when(keyStoreSpiMock.engineGetCertificate(keyAlias)).thenReturn(getTestCertificate());

        // When
        X509Certificate cert = jwkStoreServiceImpl.getCertificate(keyAlias);

        // Then
        assertThat(cert).isNotNull();
        // Must match generated test cert. To make new cert run this: (> openssl req -new -newkey rsa:512 -days 365 -nodes -x509 -keyout test.pem -out x509.pem) and fill prompts.
        assertThat(cert.getSubjectDN().getName()).isEqualTo("EMAILADDRESS=ob@forgerock.com, CN=forgerock.com, OU=ob, O=fr, L=ny, ST=ny, C=us");
    }

    @Ignore
    @Test
    public void generateJwk() throws Exception {
        // When
        final String KEYSTORE_TYPE = "PKCS12";
        final String OBRI_EXTERNAL_CA_ALIAS = "obri-external-ca";

        CertificateConfiguration certificateConfiguration = getCertificateIdentity();
        KeyPair keyPair = generateKeyPair();
        KeyStore ks = getKeyStore(KEYSTORE_TYPE);
        // Add the OBRI_EXTERNAL_CA certificate to the keystore
        ks.setCertificateEntry(OBRI_EXTERNAL_CA_ALIAS, getTestCACertificate());
        when(jwkMsConfigurationProperties.getCertificateAuthorityAlias()).thenReturn(OBRI_EXTERNAL_CA_ALIAS);
        when(mockKeyStoreService.getKeyStore()).thenReturn(ks);
        when(jwkMsConfigurationProperties.getJwkKeyStorePassword()).thenReturn(KEYSTORE_PASSWORD);

        String NEW_CERT_ALIAS = "TestCert";
        JWSAlgorithm algorithm = JWSAlgorithm.RS256;

        CSRGenerationResponse certSigningRequestResponse = new CSRGenerationResponse();
        certSigningRequestResponse.setPkcs10CertificationRequest(mock(PKCS10CertificationRequest.class));
        when(mockKeyStoreService.generatePKCS10(any(), any(), any(), any(), any())).thenReturn(certSigningRequestResponse);

        JWK cert = jwkStoreServiceImpl.generateJwk(algorithm, certificateConfiguration, NEW_CERT_ALIAS, KeyUse.SIGNATURE, keyPair);
        assertNotNull(cert);
    }


    @Test
    public void deleteKey() throws KeyStoreException {
        // ToDo
        String alias = "test-alias";
        KeyStore mockKeyStore = mock(KeyStore.class);
        when(this.mockKeyStoreService.getKeyStore()).thenReturn(this.keyStoreMock);
        Boolean deleted =  this.jwkStoreServiceImpl.deleteKey(alias);
        verify(this.mockKeyStoreService).getKeyStore();
    }

    @Ignore
    @Test
    public void toJwk() {
        //TODO: Write this test
    }

    @Test
    public void generateCSR() throws Exception {
        KeyPair keyPair = this.generateKeyPair();
        String alias = "test-csr";

        Algorithm algorithm = new Algorithm(JWSAlgorithm.RS256.toString());
        CertificateConfiguration certificateConfig = new CertificateConfiguration();
        KeyUse keyUse = KeyUse.SIGNATURE;
        CSRGenerationResponse response = mock(CSRGenerationResponse.class);
        when(this.mockKeyStoreService.generatePKCS10(alias, keyPair, algorithm, certificateConfig, keyUse))
                .thenReturn(response);

        JwkStoreServiceImpl spyJwkStoreServiceImpl = spy(this.jwkStoreServiceImpl);
        doReturn(keyPair).when(spyJwkStoreServiceImpl).getKey(alias);

        CSRGenerationResponse csr = spyJwkStoreServiceImpl.generateCSR(alias, algorithm, certificateConfig, keyUse);
        assertThat(csr).isNotNull();
    }

    @Ignore
    @Test
    public void importPem() {
        // TODO: Write this test
    }

    @Test
    public void createSelfSignedCertificateTest() throws Exception {
        // Given
        String alias = "test-cert";
        CertificateConfiguration certificateIdentity = getCertificateIdentity();
        Certificate certificationAuthority = getTestCACertificate();

        Algorithm algorithm = JWSAlgorithm.RS256;
        KeyPair keyPair = generateKeyPair();

        // When
        X509Certificate x509Cert = jwkStoreServiceImpl.createSelfSignedCertificate(alias, certificateIdentity,
                keyPair, algorithm);

        // Then

          // Verify that the generated certificate's issuer matches the certificates subject.
          // - i.e. that it is self signed.
        assertEquals(x509Cert.getSubjectX500Principal(), x509Cert.getIssuerX500Principal());

          // Verify that the new cert is signed by the CACertificate. Throws exception if verification fails.
        x509Cert.verify(keyPair.getPublic());
    }


    private KeyStore getKeyStore(String keystoreType) throws Exception {
        KeyStore ks = KeyStore.getInstance(keystoreType);
        ks.load(null, KEYSTORE_PASSWORD.toCharArray());
        return ks;
    }

    /**
     * Create a identity to be used for certificate generation.
     * @return
     */
    private CertificateConfiguration getCertificateIdentity(){
        CertificateConfiguration certificateConfiguration = new CertificateConfiguration();
        certificateConfiguration.setCn("Cn")
                .setC("C")
                .setOu("Ou")
                .setO("O")
                .setL("L")
                .setSt("St");
        return certificateConfiguration;
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }

    private Certificate getTestCertificate() throws Exception {
        final String testCertPath = "src/test/resources/x509.pem";
        return getCertFromFile(testCertPath);
    }

    private Certificate getTestCACertificate() throws Exception {
        final String testCACertPath = "src/test/resources/forgerockSelfSignedCA.crt";
        return getCertFromFile(testCACertPath);
    }

    private Certificate getCertFromFile(String path) throws IOException, CertificateException {
        FileInputStream fis = null;
        try{
            fis = new FileInputStream(path);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return certificateFactory.generateCertificate(fis);
        } finally {
            if(fis != null) fis.close();
        }
    }
}