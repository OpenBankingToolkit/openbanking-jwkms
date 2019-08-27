/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.service.jwkstore;

import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.auth.model.csr.CSRGenerationResponse;
import com.forgerock.openbanking.core.model.JwkMsKey;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;

/**
 * A JWK store is where the private key are stored.
 */
public interface JwkStoreService {

    /**
     * Get the key pair
     * @param alias
     * @return
     */
    KeyPair getKey(String alias);

    /**
     * Generate a key pair
     * @param alias key alias
     * @param certificateConfiguration certificate configuration
     * @param algorithm key algorithm
     * @param params algorithms parameter
     * @return
     */
    KeyPair generateKeyPair(String alias, CertificateConfiguration certificateConfiguration, Algorithm algorithm, AlgorithmParameterSpec params);
    /**
     * Get the private JWK behind this public JWK
     * @param key the key
     * @return the private JWK corresponding of this public JWK
     */
    JWK getPrivateJWK(JwkMsKey key);

    X509Certificate getCertificate(String alias) throws KeyStoreException;

    /**
     * Create a JWK and the keys corresponding
     * @param algorithm algorithm
     * @param certificateConfiguration
     * @param use key use
     * @param keyPair the keypair
     * @return the JWK
     */
    JWK generateJwk(Algorithm algorithm, CertificateConfiguration certificateConfiguration, String alias, KeyUse use, KeyPair keyPair);

    /**
     * Delete key
     * @param alias the alias
     * @return true if deleted with success
     */
    boolean deleteKey(String alias);

    /**
     * Convert keys into JWK
     * @param algorithm algorithm
     * @param certificate
     * @param kid the key id
     * @param keyPair the keys
     * @param use use
     * @return the JWK corresponding to this key
     */
    JWK toJwk(Algorithm algorithm, X509Certificate certificate, String kid, KeyPair keyPair, KeyUse use);

    /**
     * Generate a CSR from an existing key
     * @param algorithm
     * @param keyUse
     * @return the CSR in a certificate format
     */
    CSRGenerationResponse generateCSR(String alias, Algorithm algorithm, CertificateConfiguration certificateConfiguration, KeyUse keyUse) throws CertificateException;


    /**
     * Import the public pem to replace the existant, for a corresponding key
     * @param alias the alias
     * @param pem the pem
     */
    void importPem(String alias, String pem) throws CertificateException;

    /**
     * Sign CSR
     * @param inputCSR
     * @return
     * @throws CertificateException
     * @throws OperatorCreationException
     */
    X509Certificate signCSR(PKCS10CertificationRequest inputCSR, Certificate certificateCA, String alias) throws CertificateException, OperatorCreationException, CertIOException;


    /**
     * Creates an self signed public key certificate that proves the ownership of the public key. In this case, as it
     * is self signed, this certificate proves that we have possession of the privateKey as the private key is used to
     * sign the certificate that ties the subject to the public certificate.
     *
     * @param alias used for debug logs to identify the key pair.
     * @param subjectData Contains the identity data that the certificate will associate
     * @param keyPair Contains the public key that the certificate will bind to the identity provided in {@code subjectData}
     * @param algorithm the key algorithm
     * @return a self signed X509Certificate that associates the subject with the public key and proves that we the
     * subject holds the private key.
     * @throws CertificateException
     * @throws OperatorCreationException
     */
    X509Certificate createSelfSignedCertificate(String alias, CertificateConfiguration subjectData, KeyPair keyPair,
                                                Algorithm algorithm)

            throws CertificateException, OperatorCreationException, CertIOException;

}
