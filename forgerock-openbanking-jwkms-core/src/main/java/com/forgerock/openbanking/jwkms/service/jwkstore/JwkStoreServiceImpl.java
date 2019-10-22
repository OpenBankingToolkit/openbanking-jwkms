/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.service.jwkstore;

import com.forgerock.cert.eidas.EidasInformation;
import com.forgerock.cert.eidas.QCStatements;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.cert.utils.CertificateUtils;
import com.forgerock.openbanking.core.model.JwkMsKey;
import com.forgerock.openbanking.jwkms.config.JwkMsConfigurationProperties;
import com.forgerock.openbanking.jwkms.service.keystore.JwkKeyStoreService;
import com.forgerock.openbanking.ssl.model.csr.CSRGenerationResponse;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

/**
 * JWK store used a keystore for storing our JWKs.
 */
@Service
public class JwkStoreServiceImpl implements JwkStoreService {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwkStoreServiceImpl.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Current time minus 1 year, just in case software clock goes back due to
     * time synchronization
     */
    private static final Date NOT_BEFORE = new Date(System.currentTimeMillis() - 86400000L * 365);

    /**
     * The maximum possible value in X.509 specification: 9999-12-31 23:59:59,
     * new Date(253402300799000L), but Apple iOS 8 fails with a certificate
     * expiration date grater than Mon, 24 Jan 6084 02:07:59 GMT (issue #6).
     * <p>
     * Hundred years in the future from starting the proxy should be enough.
     */
    private static final Date NOT_AFTER = new Date(System.currentTimeMillis() + 86400000L * 365 * 100);

    public JwkStoreServiceImpl(@Autowired JwkKeyStoreService jwkKeyStoreService,
                               @Autowired JwkMsConfigurationProperties jwkMsConfigurationProperties) {
        this.jwkKeyStoreService = jwkKeyStoreService;
        this.jwkMsConfigurationProperties = jwkMsConfigurationProperties;
    }

    private JwkKeyStoreService jwkKeyStoreService;
    private JwkMsConfigurationProperties jwkMsConfigurationProperties;

    @Override
    public KeyPair getKey(String alias) {
        LOGGER.debug("Get JwkMsKey from alias {}", alias);
        try {
            KeyStore keyStore = jwkKeyStoreService.getKeyStore();
            Key key = keyStore.getKey(alias, jwkMsConfigurationProperties.getJwkKeyStorePassword().toCharArray());
            if (key == null) {
                LOGGER.debug("We couldn't find the key object behind this alias key {}", alias);
                return null;
            }
            if (key instanceof PrivateKey) {
                // Get certificate of public key
                Certificate cert = keyStore.getCertificate(alias);

                // Get public key
                PublicKey publicKey = cert.getPublicKey();

                // Return a key pair
                LOGGER.debug("We managed to get the private key from the keystore. We generate a JWK");
                return new KeyPair(publicKey, (PrivateKey) key);
            } else {
                LOGGER.error("For a reason, the key stored in the keystore wasn't a private key");
                throw new RuntimeException("The key stored in the keystore was a public key");
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            LOGGER.error("Couldn't retrieve private key", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyPair generateKeyPair(String alias, CertificateConfiguration certificateConfiguration,
                                   Algorithm algorithm, AlgorithmParameterSpec params) {
        try {
            KeyPair keyPair;
            if (KeyType.forAlgorithm(algorithm) == KeyType.RSA) {
                LOGGER.debug("Generated RSA key");
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                //TODO make the size of the key configurable
                keyGen.initialize(2048);
                LOGGER.debug("Create KeyPair");
                keyPair = keyGen.generateKeyPair();
            } else if (KeyType.forAlgorithm(algorithm) == KeyType.EC) {
                LOGGER.debug("Generated EC key");
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
                keyGen.initialize(params, new SecureRandom());
                LOGGER.debug("Create KeyPair");
                keyPair = keyGen.generateKeyPair();
            } else {
                LOGGER.error("algorithm='{}' type '{}' not implemented", algorithm, KeyType.forAlgorithm(algorithm));
                throw new IllegalArgumentException("algorithm='" + algorithm + "' type '" + KeyType.forAlgorithm
                        (algorithm) + "' not implemented");
            }
            LOGGER.debug("KeyPair created");
            return keyPair;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            LOGGER.error("Couldn't generate a new key", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public JWK getPrivateJWK(JwkMsKey key) {
        LOGGER.debug("Get private JWK behind public JWK {}", key.getJwk());
        X509Certificate cert = null;
        try {
            cert = (X509Certificate) jwkKeyStoreService.getKeyStore().getCertificate(key.getKeystoreAlias());
        } catch (KeyStoreException e) {
            LOGGER.error("Can't load certificate '{}' from keystore", key.getKeystoreAlias(), e);
            return null;
        }
        return toJwk(key.getAlgorithm(), cert, key.getKid(), getKey(key.getKeystoreAlias()), key.getKeyUse());
    }

    @Override
    public X509Certificate getCertificate(String alias) throws KeyStoreException {
        LOGGER.debug("Get certificate from alias {}", alias);
        return (X509Certificate) jwkKeyStoreService.getKeyStore().getCertificate(alias);
    }

    @Override
    public JWK generateJwk(Algorithm algorithm, CertificateConfiguration certificateConfiguration, String alias, KeyUse use, KeyPair keyPair) {
        LOGGER.debug("Generate a new JWK with algorithm {} and use {}", algorithm, use);
        X509Certificate x509Certificate = generateCertificate(algorithm, certificateConfiguration, alias, use, keyPair);
        return jwkFromCertificate(x509Certificate, algorithm, use, keyPair);
    }

    /**
     * Generates a kid (Key ID) for the certificate. According to the spec at
     * <a href="https://openbanking.atlassian.net/wiki/spaces/DZ/pages/36667724/The+OpenBanking+OpenID+Dynamic+Client
     * +Registration+Specification+-+v1.0.0-rc2#TheOpenBankingOpenIDDynamicClientRegistrationSpecification-v1.0.0-rc2-SSAheader</a>
     * then this should be a Base64 encoded SHA-1 Hash of the ASN.1 encoded certificate.
     * @param x509Cert The certificate from which to generate a kid.
     * @return A String containing the Base64 encoded SHA-1 hash of the ASN.1 encoded certificate.
     */
    private String generateKid(X509Certificate x509Cert){
        try {
            return CertificateUtils.generateB64EncodedSha1HashOfPublicKey(x509Cert);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e){
            LOGGER.info("Failed to generateKid for cert. Returning UUID.", e);
            return UUID.randomUUID().toString();
        }
    }

    private JWK jwkFromCertificate(X509Certificate x509Certificate, Algorithm algorithm, KeyUse use, KeyPair keyPair) {
        String kid = generateKid(x509Certificate);
        return toJwk(algorithm, x509Certificate, kid, keyPair, use);
    }

    @Override
    public boolean deleteKey(String kid) {
        LOGGER.debug("Delete private key behind kid {}", kid);
        try {
            jwkKeyStoreService.getKeyStore().deleteEntry(kid);
            return true;
        } catch (KeyStoreException e) {
            LOGGER.error("Couldn't delete JWK", e);
            return false;
        }
    }

    /**
     * Create the JWK from the key
     *
     * @param algorithm
     * @param keyPair   key pair
     * @return
     */
    @Override
    public JWK toJwk(Algorithm algorithm, X509Certificate certificate, String kid, KeyPair keyPair, KeyUse use) {
        LOGGER.debug("Create a JWK from algorithm {}, kid {}, keypair that we can't print and use {}",
                algorithm, kid, use);

        if (keyPair == null) {
            return null;
        }
        KeyStore keyStore = jwkKeyStoreService.getKeyStore();
        String caAlias = jwkMsConfigurationProperties.getCertificateAuthorityAlias();
        Certificate certificateCA;
        try {
            certificateCA = keyStore.getCertificate(caAlias);

            if (keyPair.getPublic() instanceof RSAPublicKey) {
                JWK jwk = RSAKey.parse(certificate);
                List<Base64> x5c = new ArrayList<>(jwk.getX509CertChain());
                x5c.add(Base64.encode(certificateCA.getEncoded()));
                LOGGER.debug("RSA keys");
                RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .privateKey((RSAPrivateKey) keyPair.getPrivate());

                builder.x509CertChain(x5c)
                        .x509CertSHA256Thumbprint(jwk.getX509CertSHA256Thumbprint())
                        .x509CertURL(jwk.getX509CertURL())
                        .algorithm(algorithm);

                return builder.keyUse(use)
                        .keyID(kid)
                        .build();
            } else if (keyPair.getPublic() instanceof ECPublicKey) {
                LOGGER.debug("EC keys");
                JWK jwk = ECKey.parse(certificate);
                List<Base64> x5c = new ArrayList<>(jwk.getX509CertChain());
                x5c.add(Base64.encode(certificateCA.getEncoded()));

                ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
                Curve curve = Curve.forECParameterSpec((ecPublicKey).getParams());
                ECKey.Builder builder = new ECKey.Builder(curve, ecPublicKey)
                        .privateKey((ECPrivateKey) keyPair.getPrivate());
                builder.x509CertChain(x5c)
                        .x509CertSHA256Thumbprint(jwk.getX509CertSHA256Thumbprint())
                        .x509CertURL(jwk.getX509CertURL());

                return builder.algorithm(algorithm)
                        .keyUse(use)
                        .keyID(kid)
                        .build();
            } else {
                LOGGER.error("keyPair should be a RSA or EC type");
                throw new IllegalArgumentException("keyPair should be a RSA or EC type ");
            }
        }  catch (JOSEException | KeyStoreException | CertificateException e) {
            LOGGER.error("Couldn't store a new key", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates a X509Certificate signed by the ForgeRock External Certificate Authority. The {@code keyPair}'s
     * privateKey is added to the keyStore (alias is the key) along with the certificateChain which contains both the
     * certificate and the ForgeRock External Certificate Authority certificate.
     * @param algorithm The algorithm to be used for the signing
     * @param certificateSubject The identity that the newly generated certificate will associate with the
     * {@code keyPair}
     * @param alias The alias that will this certificate and related information will be stored under in the key store
     * @param keyPair must contain the publicKey that will be tied to the {@code certificateSubject} in the certificate
     *                and it's associated private key.
     * @return a certificate signed by the ForgeRock External Certificate Authority.
     */
    private X509Certificate generateCertificate(Algorithm algorithm, CertificateConfiguration certificateSubject,
                                                String alias, KeyUse use, KeyPair keyPair) {

        KeyStore keyStore = jwkKeyStoreService.getKeyStore();
        String caAlias = jwkMsConfigurationProperties.getCertificateAuthorityAlias();
        try {
            // Get the ForgeRock External Certificate Authority certificate. This will be added to the certificate chain
            // for the generated certificate, and also used to sign the certificate.
            Certificate certificateCA = keyStore.getCertificate(caAlias);

            X509Certificate certificate = createSelfSignedCertificate(alias, certificateSubject, keyPair, algorithm);
            Certificate[] certChain = new Certificate[1];
            certChain[0] = certificate;
            //certChain[1] = certificateCA;

            // Store the private key of the certificate we're generating in the keystore, accessible via the alias,
            // which acts as a key for the private key of this cert.
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), jwkMsConfigurationProperties.getJwkKeyStorePassword().toCharArray(),
                    certChain);
            LOGGER.debug("Generate a CSR");
            CSRGenerationResponse csrGenerationResponse = generateCSR(alias, algorithm, certificateSubject, use);
            LOGGER.debug("Sign CSR CSR");
            PKCS10CertificationRequest pkcs10CertRequest = csrGenerationResponse.getPkcs10CertificationRequest();
            return signCSR(pkcs10CertRequest, certificateCA, caAlias);
        }  catch (KeyStoreException | CertificateException | OperatorCreationException | CertIOException e) {
            LOGGER.error("Couldn't store a new key", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public CSRGenerationResponse generateCSR(String alias, Algorithm algorithm,
                                             CertificateConfiguration certificateConfiguration, KeyUse keyUse)
            throws CertificateException {
        // Obtain a keyPair containing the privateKey associated with this alias in the KeyStore, and the publicKey
        // (obtained from the public key certificate stored in the KeyStore)
        KeyPair keyPair = getKey(alias);
        return jwkKeyStoreService.generatePKCS10(alias, keyPair, algorithm, certificateConfiguration, keyUse);
    }

    @Override
    public void importPem(String alias, String pem) throws CertificateException {
        jwkKeyStoreService.importPem(alias, pem);
    }

    /**
     * Create a certificate signed by the certificateCA.
     * @param inputCSR the Certificate Signing Request that contain the details of the certificate to be signed.
     * @param certificateCA the Certificate Authority certificate t
     * @param caAlias the alias against which the CA Certificate's private key is stored
     * @return An X509Certificate signed by the certificateCA
     * @throws CertificateException
     * @throws OperatorCreationException
     */
    @Override
    public X509Certificate signCSR(PKCS10CertificationRequest inputCSR, Certificate certificateCA, String caAlias)
            throws CertificateException, OperatorCreationException, CertIOException {
        PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(inputCSR.toASN1Structure());
        //TODO probably best to not have the CA_APP caAlias hardcoded
        LOGGER.debug("Sign CSR");

        X500Name issuerName =new JcaX509CertificateHolder((X509Certificate) certificateCA).getSubject();

        X509v3CertificateBuilder generator = new X509v3CertificateBuilder(
                issuerName,
                new BigInteger(159, new SecureRandom()),
                NOT_BEFORE,
                NOT_AFTER,
                pk10Holder.getSubject(),
                pk10Holder.getSubjectPublicKeyInfo());

        try {
            // Handle requested extensions.
            Attribute[] attributes = pk10Holder.getAttributes();
            for (Attribute attribute : attributes) {
                if (attribute.getAttrType() == PKCSObjectIdentifiers.pkcs_9_at_extensionRequest) {
                    // The CertificationRequest contains requested extensions.

                    // This next line fails because we have our own extensions. Bouncycastle doesn't
                    // yet include extensions as defined in ETSI TS 119 495 so we must interpret these
                    // ourselves. Ideally I could find a way to provide the extension classes I've written
                    // to Bouncycastle so that this code would still work.
                    ASN1Encodable[] attributeValues = attribute.getAttributeValues();
                    for (ASN1Encodable attributeValue : attributeValues) {
                        Extensions extensions = Extensions.getInstance(attributeValue);
                        Optional<QCStatements> qcStatementsOpt = QCStatements.fromExtensions(extensions);
                        if (qcStatementsOpt.isPresent()) {
                            QCStatements qcStatements = qcStatementsOpt.get();
                            ASN1ObjectIdentifier[] extOids = extensions.getExtensionOIDs();
                            for (ASN1ObjectIdentifier oid : extOids) {
                                if (oid.getId().equals(Extension.authorityInfoAccess.getId())) {
                                    AuthorityInformationAccess authAccess = AuthorityInformationAccess.fromExtensions(extensions);
                                    ASN1Primitive prim = authAccess.toASN1Primitive();
                                    generator.addExtension(oid, false, prim);
                                }
                                if (oid.getId().equals(Extension.qCStatements.getId())) {
                                    generator.addExtension(oid, false, qcStatements.toASN1Primitive());
                                }
                            }
                        }
                    }
                }
            }
        } catch (InvalidPsd2EidasCertificate e){
            LOGGER.error("Failed to add extensions from CSR", e);
        }

        return signCertificate(generator, getKey(caAlias), JWSAlgorithm.RS256);
    }

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
    public X509Certificate createSelfSignedCertificate(String alias,
                                                       CertificateConfiguration subjectData,
                                                       KeyPair keyPair, Algorithm algorithm)
            throws CertificateException, OperatorCreationException {

        LOGGER.debug("Generate a certificate for alias {}, algorithm {}", alias, algorithm);
        EidasInformation eidasInfo = subjectData.getEidasInfo();

        // Create X.500 name from the identity that is to be linked to the certificate.
        X500NameBuilder subjectNameBuilder = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, subjectData.getCn())
                .addRDN(BCStyle.OU, subjectData.getOu())
                .addRDN(BCStyle.O, subjectData.getO())
                .addRDN(BCStyle.L, subjectData.getL())
                .addRDN(BCStyle.ST, subjectData.getSt())
                .addRDN(BCStyle.C, subjectData.getC());

        // Add the contents of the certificate to the builder.
        if(eidasInfo != null){
            subjectNameBuilder.addRDN(BCStyle.ORGANIZATION_IDENTIFIER, eidasInfo.getOrganisationId());
        }

        X500Name subjectName = subjectNameBuilder.build();
        X509v3CertificateBuilder generator = new JcaX509v3CertificateBuilder(
                subjectName,
                new BigInteger(159, new SecureRandom()),
                NOT_BEFORE,
                NOT_AFTER,
                subjectName,
                keyPair.getPublic());

        return signCertificate(generator, keyPair, algorithm);
    }

    /**
     * Sign an x509 certificate with the {@code keyPair}'s privateKey.
     * @param certificateBuilder A certificate builder ready to build the certificate.
     * @param keyPair Containing the privateKey that is to be used to sign the certificate
     * @param algorithm The algorithm to be used for signing
     * @return an X509Certificate signed using the {@code keyPair}'s privateKey
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    private static X509Certificate signCertificate(
            X509v3CertificateBuilder certificateBuilder,
            KeyPair keyPair,
            Algorithm algorithm) throws OperatorCreationException, CertificateException {

        String algorithmForX509 = "";
        //TODO probably best to have those algorithm in the config instead.
        if (KeyType.forAlgorithm(algorithm) == KeyType.RSA) {
            algorithmForX509 = "SHA256WithRSA";
        } else if (KeyType.forAlgorithm(algorithm) == KeyType.EC) {
            algorithmForX509 = "SHA256withECDSA";
        }

        ContentSigner signer = new JcaContentSignerBuilder(algorithmForX509)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

        X509CertificateHolder certificateHolder = certificateBuilder.build(signer);

        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certificateHolder);
        return cert;
    }
}
