package com.puppetlabs.ssl_utils;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.binary.Hex;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.joda.time.DateTime;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.security.auth.x500.X500Principal;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLContext;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class SSLUtils {
    /**
     * The default key length to use when generating a keypair.
     */
    public static final int DEFAULT_KEY_LENGTH = 4096;

    public static final String FIPS_PROVIDER_CLASS = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
    public static final String NON_FIPS_PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    public static final String BOUNCYCASTLE_FIPS_KEYSTORE = "BCFKS";
    public static final String JAVA_KEYSTORE = "JKS";
    public static final String PKIX_KEYMANAGER_ALGO = "PKIX";
    public static final String BOUNCYCASTLE_FIPS_PROVIDER = "BCFIPS";
    public static final String BOUNCYCASTLE_JSSE_PROVIDER = "BCJSSE";
    public static final String TLS_PROTOCOL = "TLS";

    private static int crlLifetimeSeconds = 5 * 365 * 24 * 60 * 60;  // default to 5 years

    public static boolean isFIPS() {
        try {
            return getProviderClass().getCanonicalName().equals(FIPS_PROVIDER_CLASS);
        } catch(ClassNotFoundException cnfe) {
            return false;
        }
    }

    public static Class getProviderClass() throws ClassNotFoundException {
        Class clazz;
        try {
            clazz = Class.forName(FIPS_PROVIDER_CLASS);
        } catch(ClassNotFoundException cnf) {
            // if FIPS isn't present, attempt to use the non-FIPS provider. If this fails,
            // the exception is allow to propagate
            clazz = Class.forName(NON_FIPS_PROVIDER_CLASS);
        }

        return clazz;
    }

    /**
     * Create new public & private keys with length 4096.
     *
     * @return A new pair of public & private keys
     * @throws NoSuchAlgorithmException
     * @see #generateKeyPair(int)
     */
    public static KeyPair generateKeyPair()
        throws NoSuchAlgorithmException
    {
        return generateKeyPair(DEFAULT_KEY_LENGTH);
    }

    /**
     * Create new public & private keys of the provided length.
     *
     * @return A new pair of public & private keys
     * @throws NoSuchAlgorithmException
     * @see #generateKeyPair()
     */
    public static KeyPair generateKeyPair(int keyLength)
        throws NoSuchAlgorithmException
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keyLength);
        return keyGen.generateKeyPair();
    }

    /**
     * Given an X500Name, return the common name from it.
     *
     * @param x500Name The X500 name string to extract from
     * @return The common name from the X500Name.  Empty string if none available.
     */
    public static String getCommonNameFromX500Name(String x500Name) {
        RDN[] rdns = new X500Name(BCStyle.INSTANCE, x500Name).getRDNs(BCStyle.CN);
        String commonName = "";
        if (rdns.length > 0) {
            AttributeTypeAndValue attributeInfo = rdns[0].getFirst();
            if (attributeInfo != null) {
                commonName = attributeInfo.getValue().toString();
            }
        }
        return commonName;
    }

    /**
     * Given the subject's keypair and name, create and return a certificate signing request (CSR).
     * If the extensions parameter is not null and is a list of size great than 0, they will be
     * added to this request.
     *
     * @param keyPair The subject's public and private keys.
     * @param subjectDN The subject's CN.
     * @param extensions Extensions to add to this cert request.
     * @param attributes to add to this cert request (converted to strings)
     * @return A request to certify the provided subject
     * @throws IOException
     * @throws OperatorCreationException
     * @see #generateKeyPair
     */
    public static PKCS10CertificationRequest generateCertificateRequest(KeyPair keyPair, String subjectDN,
        List<Map<String, Object>> extensions, List<Map<String, Object>> attributes)
        throws IOException, OperatorCreationException, CertificateEncodingException
    {
        // TODO: the puppet code sets a property "version=0" on the request object
        // here; can't figure out how to do that at the moment.  Not sure if it's needed.
        PKCS10CertificationRequestBuilder requestBuilder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name(BCStyle.INSTANCE, subjectDN), keyPair.getPublic());

        if ((extensions != null) && (extensions.size() > 0)) {
            Extensions parsedExts = ExtensionsUtils.getExtensionsObjFromMap(extensions);
            requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, parsedExts);
        }

        if ((attributes != null) && (attributes.size() > 0)) {
            HashMap<String, ArrayList<ASN1Encodable>> mappedEntries = new HashMap<String, ArrayList<ASN1Encodable>>();
            for (Map<String, Object> attributeMap : attributes) {
                String oidString = (String)attributeMap.get("oid");
                String value = attributeMap.get("value").toString();
                DEROctetString convertedValue = new DEROctetString(
                        new DERUTF8String(value));
                if (mappedEntries.containsKey(oidString)) {
                    mappedEntries.get(oidString).add(convertedValue);
                } else {
                    ArrayList<ASN1Encodable> newValues = new ArrayList<ASN1Encodable>();
                    newValues.add(convertedValue);
                    mappedEntries.put(oidString, newValues);
                }

            }
            for (Map.Entry<String, ArrayList<ASN1Encodable>> entry: mappedEntries.entrySet()) {
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(entry.getKey());
                ArrayList<ASN1Encodable> values = entry.getValue();
                ASN1Encodable[] convertedValues = new ASN1Encodable[entry.getValue().size()];
                values.toArray(convertedValues);
                requestBuilder.addAttribute(oid, convertedValues);
            }
        }

        return requestBuilder.build(
                new JcaContentSignerBuilder("SHA1withRSA").
                        build(keyPair.getPrivate()));
    }

    /**
     * Given certificate authority information, expiration dates, and the
     * subject's name and public key info, create a newly signed certificate.
     * If the extensions parameter is not null then all the maps in the list
     * will be parsed into extensions and written on to the certificate.
     *
     * @param issuerDn A string containing the issuer's distinguished name.
     * @param issuerPrivateKey The issuer's private key
     * @param serialNumber Serial number to assign the generated certificate.
     * @param notBefore Date to assign to the not-before field.
     * @param notAfter Date to assign to the not-after field.
     * @param subjectDn A string containing the subject's distinguished name.
     * @param subjectPublicKey The subject's public key
     * @param extensions A list of maps which contain extensions that are to be
     *                   written to the signed certificate.
     * @return The newly signed certificate.
     * @throws IOException
     * @throws OperatorCreationException
     * @throws CertificateException
     * @see com.puppetlabs.ssl_utils.ExtensionsUtils#getExtensionsObjFromMap(java.util.List)
     */
    public static X509Certificate signCertificate(String issuerDn,
                                                  PrivateKey issuerPrivateKey,
                                                  BigInteger serialNumber,
                                                  Date notBefore, Date notAfter,
                                                  String subjectDn,
                                                  PublicKey subjectPublicKey,
                                                  List<Map<String, Object>> extensions)
            throws IOException, OperatorCreationException, CertificateException
    {
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                new X500Name(BCStyle.INSTANCE, issuerDn),
                serialNumber,
                notBefore,
                notAfter,
                new X500Name(BCStyle.INSTANCE, subjectDn),
                SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded()));

        Extensions bcExtensions = ExtensionsUtils.getExtensionsObjFromMap(extensions);

        if (bcExtensions != null) {
            for (ASN1ObjectIdentifier oid : bcExtensions.getNonCriticalExtensionOIDs()) {
                certBuilder.addExtension(oid, false, bcExtensions.getExtension(oid).getParsedValue());
            }

            for (ASN1ObjectIdentifier oid : bcExtensions.getCriticalExtensionOIDs()) {
                certBuilder.addExtension(oid, true, bcExtensions.getExtension(oid).getParsedValue());
            }
        }

        AlgorithmIdentifier sigAlgId =
                new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");

        AlgorithmIdentifier digAlgId =
                new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");

        ContentSigner signer = builder.build(issuerPrivateKey);

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

        return converter.getCertificate(certBuilder.build(signer));
    }

    /**
     * Given the certificate authority's principal identifier and private
     * & public keys, create a new certificate revocation list (CRL).
     *
     * The CRL will have an AuthorityKeyIdentifier extension and CRLNumber
     * extension, set to 0 unless otherwise specified.
     *
     * @param issuer The certificate authority's identifier
     * @param issuerPrivateKey The certificate authority's private key
     * @param issuerPublicKey The certificate authority's public key
     * @param thisUpdate The date after which this CRL becomes valid
     * @param nextUpdate The date by which an updated CRL is expected
     * @param crlNumber The CRL Number for this CRL, used to identify how new a
     *                  CRL is compared to another CRL from the same issuer
     * @param extensions An optional list of extensions to include, in addition
     *                   to AuthorityKeyIdentifier and CRLNumber.
     * @return A new certificate revocation list
     * @throws CRLException
     * @throws IOException
     * @throws OperatorCreationException
     * @see #revoke
     * @see #isRevoked
     */
    public static X509CRL generateCRL(X500Principal issuer,
                                      PrivateKey issuerPrivateKey,
                                      PublicKey issuerPublicKey,
                                      Date thisUpdate,
                                      Date nextUpdate,
                                      BigInteger crlNumber,
                                      List<Map<String, Object>> extensions)
        throws CRLException, IOException, OperatorCreationException, NoSuchAlgorithmException, CertificateEncodingException
    {
        X509v2CRLBuilder builder = new JcaX509v2CRLBuilder(issuer, thisUpdate);
        builder.setNextUpdate(nextUpdate);
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(crlNumber));
        Extensions bcExtensions = ExtensionsUtils.getExtensionsObjFromMap(extensions);
        if (bcExtensions != null) {
            for (ASN1ObjectIdentifier oid : bcExtensions.getNonCriticalExtensionOIDs()) {
                builder.addExtension(oid, false, bcExtensions.getExtension(oid).getParsedValue());
            }

            for (ASN1ObjectIdentifier oid : bcExtensions.getCriticalExtensionOIDs()) {
                builder.addExtension(oid, true, bcExtensions.getExtension(oid).getParsedValue());
            }
        }
        if (builder.hasExtension(Extension.authorityKeyIdentifier) == false) {
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                                 new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuerPublicKey));
        }
        ContentSigner signer =
            new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        return new JcaX509CRLConverter().getCRL(builder.build(signer));
    }

    public static X509CRL generateCRL(X500Principal issuer,
                                      PrivateKey issuerPrivateKey,
                                      PublicKey issuerPublicKey)
        throws CRLException, IOException, OperatorCreationException, NoSuchAlgorithmException, CertificateEncodingException
    {
        DateTime now = DateTime.now();
        Date thisUpdate = now.toDate();
        Date nextUpdate = now.plusSeconds(crlLifetimeSeconds).toDate();
        return generateCRL(issuer, issuerPrivateKey, issuerPublicKey,
                           thisUpdate, nextUpdate, BigInteger.ZERO, null);
    }

    /**
     * Given a certificate revocation list and certificate,
     * test if the certificate has been revoked.
     *
     * Note that if the certificate and CRL have different issuers,
     * {@code false} will be returned even if the certificate's
     * serial number is on the CRL (i.e. previously revoked).
     *
     * @param crl The certificate revocation list to check
     * @param certificate The certificate to check
     * @return {@code true} if the certificate is on the revocation list,
               {@code false} otherwise.
     * @see #revoke
     * @see #generateCRL
     */
    public static boolean isRevoked(X509CRL crl, X509Certificate certificate) {
        return crl.isRevoked(certificate);
    }

    private static X509v2CRLBuilder crlBuilder(X509CRL crl)
            throws CRLException {
        // The CRL is not valid if the time of checking == the time of last_update.
        // So to have it valid right now we need to say that it was updated one second ago.
        DateTime now = DateTime.now();
        Date thisUpdate = now.minusSeconds(1).toDate();
        Date nextUpdate = now.plusYears(5).toDate();
        X509v2CRLBuilder builder =
                new JcaX509v2CRLBuilder(crl.getIssuerX500Principal(), thisUpdate);
        builder.setNextUpdate(nextUpdate);
        // Copy over existing CRLEntrys
        builder.addCRL(new JcaX509CRLHolder(crl));
        return builder;
    }

    private static X509CRL buildCRL(X509CRL crl,
                                    PrivateKey issuerPrivateKey,
                                    PublicKey issuerPublicKey,
                                    X509v2CRLBuilder builder)
            throws IOException, CRLException, NoSuchAlgorithmException, OperatorCreationException {
        BigInteger crlNumber = (BigInteger)
                ExtensionsUtils.getExtensionValue(crl, ExtensionsUtils.CRL_NUMBER_OID);
        crlNumber = (crlNumber == null) ? BigInteger.ZERO : crlNumber;
        builder.addExtension(Extension.cRLNumber, false,
                new CRLNumber(crlNumber.add(BigInteger.ONE)));
        JcaX509CRLHolder holder = new JcaX509CRLHolder(crl);
        Extension extension = holder.getExtension(Extension.authorityKeyIdentifier);
        if (extension == null) {
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                                 new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuerPublicKey));
            }
        else {
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                                 extension.getParsedValue());

        }

        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        return new JcaX509CRLConverter().getCRL(builder.build(signer));
    }

    /**
     * Given a certificate revocation list and certificate serial number,
     * add the certificate to the revocation list and return the updated
     * CRL. The issuer keys should be the same keys that were used when
     * generating the CRL.
     *
     * The CRLNumber extension on the CRL will be incremented by 1, or
     * the extension will be added if it doesn't already exist.
     *
     * The AuthorityKeyIdentifier extension will be added to the CRL if
     * if doesn't already exist. If the original CRL already has an
     * AuthorityKeyIdentifier it will be copied into the new CRL,
     * otherwise one will be computed from the issuerPublicKey.
     *
     * @param crl The revocation list to add the certificate serial to
     * @param issuerPrivateKey The certificate authority's private key
     * @param issuerPublicKey The certificate authority's public key
     * @param serial The serial number from the certificate to revoke
     * @return The updated CRL containing the revoked certificate serial
     * @throws CRLException
     * @throws IOException
     * @throws CertIOException
     * @throws OperatorCreationException
     * @see #isRevoked
     * @see #generateCRL
     */
    public static X509CRL revoke(X509CRL crl,
                                 PrivateKey issuerPrivateKey,
                                 PublicKey issuerPublicKey,
                                 BigInteger serial)
            throws CRLException, IOException, NoSuchAlgorithmException, OperatorCreationException {
        X509v2CRLBuilder builder = crlBuilder(crl);
        // TODO PE-5678 Use java.security.cert.CRLReason.KEY_COMPROMISE.ordinal() instead of 1
        builder.addCRLEntry(serial, DateTime.now().toDate(), 1);
        return buildCRL(crl, issuerPrivateKey, issuerPublicKey, builder);
    }

    /**
     * Given a certificate revocation list and a list of certificate
     * serial numbers, add the certificates to the revocation list and
     * return the updated CRL. The issuer keys should be the same keys
     * that were used when generating the CRL.
     *
     * The CRLNumber extension on the CRL will be incremented by 1, or
     * the extension will be added if it doesn't already exist.
     *
     * The AuthorityKeyIdentifier extension will be added to the CRL if
     * if doesn't already exist. If the original CRL already has an
     * AuthorityKeyIdentifier it will be copied into the new CRL,
     * otherwise one will be computed from the issuerPublicKey.
     *
     * @param crl The revocation list to add the certificate serials to
     * @param issuerPrivateKey The certificate authority's private key
     * @param issuerPublicKey The certificate authority's public key
     * @param serials The serial numbers from the certificates to revoke
     * @return The updated CRL containing the revoked certificate serials
     * @throws CRLException
     * @throws IOException
     * @throws CertIOException
     * @throws OperatorCreationException
     * @see #isRevoked
     * @see #generateCRL
     */
    public static X509CRL revokeMultiple(X509CRL crl,
                                 PrivateKey issuerPrivateKey,
                                 PublicKey issuerPublicKey,
                                 List<BigInteger> serials)
            throws CRLException, IOException, NoSuchAlgorithmException, OperatorCreationException {
        X509v2CRLBuilder builder = crlBuilder(crl);
        // TODO PE-5678 Use java.security.cert.CRLReason.KEY_COMPROMISE.ordinal() instead of 1
        for (BigInteger serial : serials) {
            builder.addCRLEntry(serial, DateTime.now().toDate(), 1);
        }
        return buildCRL(crl, issuerPrivateKey, issuerPublicKey, builder);
    }

    /**
     * Given a list of certificates and a list of CRLs, validate the certificate
     * chain, i.e. ensure that none of the certs have been revoked by checking
     * the appropriate CRL, which must be present and currently valid.
     * Returns nil if successful."
     *
     * @param certs The certificate chain to validate
     * @param crls The CRL chain to validate
     * @throws CertificateException
     * @throws CertPathValidatorException
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static void validateCertChain(List<X509Certificate> certs,
                                         List<X509CRL> crls)
        throws CertificateException, CertPathValidatorException, IOException,
               InvalidAlgorithmParameterException, KeyStoreException,
               NoSuchAlgorithmException, NoSuchProviderException {
        final CertificateFactory certFactory;
        final CertPathValidator validator;
        final CertStore crlStore;
        final CollectionCertStoreParameters storeParams = new CollectionCertStoreParameters(crls);
        if (isFIPS()) {
            certFactory = CertificateFactory.getInstance("X.509", BOUNCYCASTLE_FIPS_PROVIDER);
            validator = CertPathValidator.getInstance(PKIX_KEYMANAGER_ALGO, BOUNCYCASTLE_FIPS_PROVIDER);
            crlStore = CertStore.getInstance("Collection", storeParams, BOUNCYCASTLE_FIPS_PROVIDER);
        } else {
            certFactory = CertificateFactory.getInstance("X.509");
            validator = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
            crlStore = CertStore.getInstance("Collection", storeParams);
        }
        final CertPath certPath = certFactory.generateCertPath(certs);
        final KeyStore truststore = certsToTrustStore(certs);
        PKIXBuilderParameters params =
                new PKIXBuilderParameters(truststore, new X509CertSelector());
        params.addCertStore(crlStore);
        validator.validate(certPath, params);
    }

    /**
     * Given a PEM reader, decode the contents into a certificate revocation list.
     *
     * @param reader Reader for a PEM-encoded stream
     * @return The decoded certificate revocation list from the stream
     * @throws IOException
     * @throws CRLException
     * @see #generateCRL
     */
    public static X509CRL pemToCRL(Reader reader)
        throws IOException, CRLException
    {
        List<Object> pemObjects = pemToObjects(reader);
        if (pemObjects.size() > 1)
            throw new IllegalArgumentException("The PEM stream contains more than one object");
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        return converter.getCRL((X509CRLHolder) pemObjects.get(0));
    }

    /**
     * Given a PEM reader, decode the contents into a list of certificate
     * revocation lists.
     *
     * @param reader Reader for a PEM-encoded stream
     * @return The list of certificate revocation list objects decoded from the
     *         stream
     * @throws IOException
     * @throws CRLException
     * @see #generateCRL
     */
    public static List<X509CRL> pemToCRLs(Reader reader)
            throws IOException, CRLException
    {
        List<Object> pemObjects = pemToObjects(reader);
        List<X509CRL> results = new ArrayList<X509CRL>(pemObjects.size());
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        for (Object o : pemObjects)
            results.add(converter.getCRL((X509CRLHolder) o));
        return results;
    }

    /**
     * Given a PEM reader, decode the contents into a certificate signing request.
     *
     * @param reader Reader for a PEM-encoded stream
     * @return The decoded certification request from the stream
     * @throws IOException
     * @see #writeToPEM
     */
    public static PKCS10CertificationRequest pemToCertificateRequest(Reader reader)
        throws IOException
    {
        List<Object> pemObjects = pemToObjects(reader);
        if (pemObjects.size() > 1)
            throw new IllegalArgumentException("The PEM stream contains more than one object");
        return (PKCS10CertificationRequest) pemObjects.get(0);
    }

    /**
     * Create an empty in-memory key store.
     *
     * @return New key store
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static KeyStore createKeyStore()
        throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        final String keystoreType;
        if (isFIPS()) {
            keystoreType = BOUNCYCASTLE_FIPS_KEYSTORE;
        } else {
            keystoreType = JAVA_KEYSTORE;
        }
        KeyStore ks = KeyStore.getInstance(keystoreType);
        ks.load(null, null);
        return ks;
    }

    /**
     * Given a PEM reader, decode the contents into a collection of objects of the corresponding
     * type from the java.security package.
     *
     * @param reader Reader for a PEM-encoded stream
     * @return The list of decoded objects from the stream
     * @throws IOException
     * @see #writeToPEM
     */
    public static List<Object> pemToObjects(Reader reader)
        throws IOException
    {
        PEMParser parser = new PEMParser(reader);
        List<Object> results = new ArrayList<Object>();
        for (Object o = parser.readObject(); o != null; o = parser.readObject())
            results.add(o);
        return results;
    }

    /**
     * Encodes an object in PEM format and writes it to the stream.
     *
     * @param obj The object to encode and write. Must be of a type that can be encoded to PEM.
     *            Usually this is limited to certain types from the java.security package
     * @param writer The stream to write the encoded object to
     * @throws IOException
     * @see #pemToObjects
     * @see #pemToCerts
     * @see #pemToPrivateKeys
     * @see #pemToPrivateKey
     * @see #pemToCertificateRequest
     */
    public static void writeToPEM(Object obj, Writer writer)
        throws IOException
    {
        JcaPEMWriter pw = new JcaPEMWriter(writer);
        pw.writeObject(obj);
        pw.flush();
    }

    /**
     * Given a PEM reader, decode the contents into a list of certificates.
     *
     * @param reader Reader for a PEM-encoded stream
     * @return The list of decoded certificates from the stream
     * @throws CertificateException
     * @throws IOException
     * @see #writeToPEM
     */
    public static List<X509Certificate> pemToCerts(Reader reader)
        throws CertificateException, IOException
    {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        List<Object> pemObjects = pemToObjects(reader);
        List<X509Certificate> results = new ArrayList<X509Certificate>(pemObjects.size());
        for (Object o : pemObjects)
            results.add(converter.getCertificate((X509CertificateHolder) o));
        return results;
    }

    /**
     * Given a certificate and public key, test whether the public key in the certificate matches
     * the expected public key.
     *
     * @param cert certificate The certificate to test
     * @param pubKey the expected public key
     * @return {@code true} if the certificate matches the public key, {@code false} otherwise.
     */
    public static boolean certMatchesPubKey(X509Certificate cert, PublicKey pubKey) {
        PublicKey extractedPubKey = cert.getPublicKey();

        return extractedPubKey.getFormat().equals(pubKey.getFormat()) &&
            extractedPubKey.getAlgorithm().equals(pubKey.getAlgorithm()) &&
            Arrays.equals(extractedPubKey.getEncoded(), pubKey.getEncoded());
    }

    /**
     * Given a PEM reader for a CA certificate chain and a PEM reader for a public key,
     * verify and return the certificate that matches the given key.
     *
     * @param certChainReader Reader for a PEM-encoded stream of X.509 certificates
     * @param keyReader Reader for a PEM-encoded blob from which a PublicKey is extracted via {@link #pemToPublicKey}
     * @return The certificate in the certificate stream matching the given key
     * @throws CertificateException
     * @throws IOException
     * @throws IllegalArgumentException if the cert chain is empty or doesn't contain a cert matching the public key in the key pair
     */
    public static X509Certificate pemToCaCert(Reader certChainReader, Reader keyReader)
        throws CertificateException, IOException
    {
        List<X509Certificate> certs = pemToCerts(certChainReader);
        if (certs.size() < 1)
            throw new IllegalArgumentException("The certificate PEM stream must contain at least 1 certificate");

        PublicKey caPubkey = pemToPublicKey(keyReader);
        Optional<X509Certificate> caCert = certs.stream().filter((cert) -> certMatchesPubKey(cert, caPubkey)).findFirst();
        return caCert.orElseThrow(() -> new IllegalArgumentException("The certificate chain does not contain a certificate that matches the expected public key"));
    }

    /**
     * Given a PEM reader, decode the contents into a certificate.
     * Throws an exception if multiple certificates are found.
     *
     * @param reader Reader for a PEM-encoded stream
     * @return The certificate decoded from the stream
     * @throws CertificateException
     * @throws IOException
     * @see #writeToPEM
     */
    public static X509Certificate pemToCert(Reader reader)
        throws CertificateException, IOException
    {
        List<X509Certificate> certs = pemToCerts(reader);
        if (certs.size() != 1)
            throw new IllegalArgumentException("The PEM stream must contain exactly 1 certificate");
        return certs.get(0);
    }

    /**
     * Decodes the provided object (read from a PEM stream via {@link #pemToObjects}) into a private key.
     *
     * @param obj The object to decode into a PrivateKey
     * @return The PrivateKey decoded from the object
     * @throws PEMException
     * @see #pemToPrivateKey
     * @see #pemToPrivateKeys
     */
    public static PrivateKey objectToPrivateKey(Object obj)
        throws PEMException
    {
        // Certain PEMs will hand back a keypair with a nil public key
        if (obj instanceof PrivateKeyInfo)
            return new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) obj);
        else if (obj instanceof PEMKeyPair)
            return new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) obj).getPrivate();
        else
            throw new IllegalArgumentException("Expected a KeyPair or PrivateKey, got " + obj);
    }

    /**
     * Given a PEM reader, decode the contents into a list of private keys.
     *
     * @param reader Reader for a PEM-encoded stream
     * @return The list of decoded private keys from the stream
     * @throws IOException
     * @throws PEMException
     * @see #pemToPrivateKey
     * @see #writeToPEM
     */
    public static List<PrivateKey> pemToPrivateKeys(Reader reader)
        throws IOException
    {
        List<Object> objects = pemToObjects(reader);
        List<PrivateKey> results = new ArrayList<PrivateKey>(objects.size());
        for (Object o : objects) {
            // Filter out EC params; this passes every other
            // kind of object through to `objectToPrivateKey`,
            // which will throw if the object is not a key
            if (!(o instanceof ASN1ObjectIdentifier)) {
                results.add(objectToPrivateKey(o));
            }
        }
        return results;
    }

    /**
     * Given a PEM reader, decode the contents into a private key.
     * Throws an exception if multiple keys are found.
     *
     * @param reader Reader for a PEM-encoded stream
     * @return The decoded private key from the stream
     * @throws IOException
     * @throws IllegalArgumentException
     * @see #pemToPrivateKeys
     * @see #writeToPEM
     */
    public static PrivateKey pemToPrivateKey(Reader reader)
        throws IOException
    {
        List<PrivateKey> privateKeys = pemToPrivateKeys(reader);
        if (privateKeys.size() != 1)
            throw new IllegalArgumentException("The PEM stream must contain exactly one private key");
        return privateKeys.get(0);
    }

    /**
     * Given a PEM reader, decode the contents into a public key.
     * Throws an exception if multiple keys are found.
     *
     * @param reader Reader for a PEM-encoded stream
     * @return The decoded public key from the stream
     * @throws IOException
     * @see #writeToPEM
     */
    public static PublicKey pemToPublicKey(Reader reader)
        throws IOException
    {
        List<Object> objects = pemToObjects(reader);
        if (objects.size() != 1)
            throw new IllegalArgumentException("The PEM stream must contain exactly one object");

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        Object object = objects.get(0);
        if (object instanceof SubjectPublicKeyInfo)
          return converter.getPublicKey((SubjectPublicKeyInfo) object);

        else if (object instanceof PEMKeyPair)
          return converter.getKeyPair((PEMKeyPair) object).getPublic();

        else if (object instanceof PrivateKeyInfo) {
          // See https://github.com/apache/nifi/blob/rel/nifi-1.9.2/nifi-toolkit/nifi-toolkit-tls/src/main/java/org/apache/nifi/toolkit/tls/util/TlsHelper.java#L243-L261
          PrivateKeyInfo keyHolder = (PrivateKeyInfo) object;
          RSAPrivateKey keyStruct = RSAPrivateKey.getInstance(keyHolder.parsePrivateKey());
          RSAPublicKey pubKeySpec = new RSAPublicKey(keyStruct.getModulus(), keyStruct.getPublicExponent());
          AlgorithmIdentifier algId = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
          SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(algId, pubKeySpec);
          return converter.getPublicKey(pubKeyInfo);

        } else {
          throw new IllegalArgumentException("Could not recognize object in PEM stream");
        }
    }

    /**
     * Given a PEM reader, decode the contents into a list of key pairs.
     * @param reader Reader for a PEM-encoded stream
     * @return The list of decoded key pairs from the stream
     * @throws IOException
     * @throws PEMException
     * @see #pemToKeyPair
     */
    public static List<KeyPair> pemToKeyPairs(Reader reader)
        throws IOException
    {
        List<Object> objects = pemToObjects(reader);
        List<KeyPair> results = new ArrayList<KeyPair>(objects.size());
        JcaPEMKeyConverter c = new JcaPEMKeyConverter();
        for (Object o : objects) {
            if (o instanceof PEMKeyPair)
                results.add(c.getKeyPair((PEMKeyPair) o));
            else
                throw new IllegalArgumentException("Expected a KeyPair, got " + o);
        }
        return results;
    }

    /**
     * Given a PEM reader, decode the contents into a key pair.
     * Throws an exception if multiple key pairs are found.
     *
     * @param reader Reader for a PEM-encoded stream
     * @return The decoded key pair from the stream
     * @throws IOException
     * @throws IllegalArgumentException
     * @see #pemToKeyPairs
     */
    public static KeyPair pemToKeyPair(Reader reader)
        throws IOException
    {
        List<KeyPair> keyPairs = pemToKeyPairs(reader);
        if (keyPairs.size() != 1)
            throw new IllegalArgumentException("The PEM stream must contain exactly one key pair");
        return keyPairs.get(0);
    }

    /**
     * Add a certificate to a keystore.
     *
     * @param keystore The keystore to add the certificate to
     * @param alias An alias to associate with the certificate
     * @param cert The certificate to add to the keystore
     * @return The provided keystore
     * @throws KeyStoreException
     * @see #associateCertsFromReader
     */
    public static KeyStore associateCert(KeyStore keystore, String alias, X509Certificate cert)
        throws KeyStoreException
    {
        keystore.setCertificateEntry(alias, cert);
        return keystore;
    }

    /**
     * Add all certificates to the keystore.
     *
     * @param keystore The keystore to add all the certificates to
     * @param prefix An alias to associate with the certificates. Each certificate will
     *               have a numeric index appended to the prefix (starting with '-0')
     * @param certs List of certificates to add to the keystore
     * @return The provided keystore
     * @throws KeyStoreException
     * @see #associateCert
     */
    public static KeyStore associateCertsFromList(KeyStore keystore, String prefix, List<X509Certificate> certs)
            throws KeyStoreException
    {
        ListIterator<X509Certificate> iter = certs.listIterator();
        for (int i = 0; iter.hasNext(); i++)
            associateCert(keystore, prefix + "-" + i, iter.next());
        return keystore;
    }

    /**
     * Add all certificates from a PEM reader to the keystore.
     *
     * @param keystore The keystore to add all the certificates to
     * @param prefix An alias to associate with the certificates. Each certificate will
     *               have a numeric index appended to the prefix (starting with '-0')
     * @param pem Reader for a PEM-encoded stream of certificates
     * @return The provided keystore
     * @throws CertificateException
     * @throws KeyStoreException
     * @throws IOException
     * @see #associateCert
     */
    public static KeyStore associateCertsFromReader(KeyStore keystore, String prefix, Reader pem)
        throws CertificateException, KeyStoreException, IOException
    {
        List<X509Certificate> certs = pemToCerts(pem);
        return associateCertsFromList(keystore, prefix, certs);
    }

    /**
     * Add a private key to a keystore.
     *
     * @param keystore The keystore to add the private key to
     * @param alias An alias to associate with the private key
     * @param privateKey The private key to add to the keystore
     * @param password To protect the key in the keystore
     * @param cert The certificate for the private key; a private key cannot
     *             be added to a keystore without a signed certificate
     * @return The provided keystore
     * @throws KeyStoreException
     * @see #associatePrivateKeyFromReader
     */
    public static KeyStore associatePrivateKey(KeyStore keystore,
                                               String alias,
                                               PrivateKey privateKey,
                                               String password,
                                               X509Certificate cert)
        throws KeyStoreException
    {
        if (cert == null)
            throw new IllegalArgumentException(
                    "associatePrivateKey requires a value for a cert");

        List<X509Certificate> certs = new ArrayList<X509Certificate>(1);
        certs.add(cert);

        associatePrivateKey(keystore, alias, privateKey, password, certs);
        return keystore;
    }

    /**
     * Add a private key to a keystore.
     *
     * @param keystore The keystore to add the private key to
     * @param alias An alias to associate with the private key
     * @param privateKey The private key to add to the keystore
     * @param password To protect the key in the keystore
     * @param certs A list of certificates for the private key.  The first
     *              certificate in the list should be the "leaf" certificate.
     *              Additional optional entries in the list represent the CA
     *              certificate(s) from which the "leaf" certificate derives.
     *              CA certificate entries should appear in hierarchical
     *              order from the most derived intermediate CA (second in
     *              the list, if applicable) to the root CA (last in the
     *              list).  Note that the privateKey parameter should be the
     *              private key associated with the first, "leaf", certificate
     *              in the list.
     * @return The provided keystore
     * @throws IllegalArgumentException if certs does not contain a list with
     *                                  at least one certificate
     * @throws KeyStoreException
     * @see #associatePrivateKeyFromReader
     */
    public static KeyStore associatePrivateKey(KeyStore keystore,
                                               String alias,
                                               PrivateKey privateKey,
                                               String password,
                                               List<X509Certificate> certs)
            throws KeyStoreException
    {
        if (certs == null || certs.size() == 0)
            throw new IllegalArgumentException("associatePrivateKey requires at least one cert");

        X509Certificate[] certsArray = new X509Certificate[certs.size()];
        certs.toArray(certsArray);

        keystore.setKeyEntry(alias, privateKey, password.toCharArray(), certsArray);
        return keystore;
    }

    /**
     * Add the private key from a PEM reader to the keystore.
     *
     * @param keystore The keystore to add the private key to
     * @param alias An alias to associate with the private key
     * @param pemPrivateKey Reader for a PEM-encoded stream with the private key
     * @param password To protect the key in the keystore
     * @param pemCert Reader for a PEM-encoded stream with the certificate; a private
     *                key cannot be added to a keystore without a signed certificate
     * @return The provided keystore
     * @throws CertificateException
     * @throws KeyStoreException
     * @throws IOException
     * @see #associatePrivateKey
     */
    public static KeyStore associatePrivateKeyFromReader(KeyStore keystore,
                                                         String alias,
                                                         Reader pemPrivateKey,
                                                         String password,
                                                         Reader pemCert)
        throws CertificateException, KeyStoreException, IOException
    {
        PrivateKey privateKey = pemToPrivateKey(pemPrivateKey);
        List<X509Certificate> certs = pemToCerts(pemCert);

        if (certs.size() < 1)
            throw new IllegalArgumentException(
                    "The PEM stream contains no certificates");

        return associatePrivateKey(keystore, alias, privateKey, password,
                certs);
    }

    /**
     * Given PEM readers for a certificate, private key, and CA certificate,
     * create an in-memory keystore and truststore.
     *
     * Returns a map containing the following:
     * <ul>
     *  <li>"keystore" - a keystore initialized with the cert and private key</li>
     *  <li>"keystore-pw" - a string containing a dynamically generated password for the keystore</li>
     *  <li>"truststore" - a keystore containing the CA cert</li>
     * <ul>
     *
     * @param cert Reader for a PEM-encoded stream with the certificate
     * @param privateKey Reader for a PEM-encoded stream with the correspnding private key
     * @param caCert Reader for a PEM-encoded stream with the CA certificate
     * @return Map containing the keystore, keystore password, and truststore
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public static Map<String, Object> pemsToKeyAndTrustStores(Reader cert, Reader privateKey, Reader caCert)
        throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException
    {
        KeyStore truststore = createKeyStore();
        associateCertsFromReader(truststore, "CA Certificate", caCert);

        KeyStore keystore = createKeyStore();
        String keystorePassword = UUID.randomUUID().toString();
        associatePrivateKeyFromReader(keystore, "Private Key", privateKey, keystorePassword, cert);

        Map<String, Object> result = new HashMap<String, Object>();
        result.put("truststore", truststore);
        result.put("keystore", keystore);
        result.put("keystore-pw", keystorePassword);
        return result;
    }

    /**
     * Given a keystore and keystore password (as generated by {@link #pemsToKeyAndTrustStores}),
     * return a key manager factory that contains the keystore.
     *
     * @param keystore The keystore to get a key manager for
     * @param password The password for the keystore
     * @return A key manager factory for the provided keystore
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     */
    public static KeyManagerFactory getKeyManagerFactory(KeyStore keystore, String password)
        throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, NoSuchProviderException
    {
        final KeyManagerFactory factory;
        if (isFIPS()) {
            factory = KeyManagerFactory.getInstance(PKIX_KEYMANAGER_ALGO, BOUNCYCASTLE_JSSE_PROVIDER);
        } else {
            factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        }
        factory.init(keystore, password.toCharArray());
        return factory;
    }

    private static KeyManagerFactory getKeyManagerFactory(
            Map<String, Object> stores)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchProviderException
    {
        KeyStore keystore = (KeyStore) stores.get("keystore");
        String password = (String) stores.get("keystore-pw");
        return getKeyManagerFactory(keystore, password);
    }

    /**
     * Given a truststore (as generated by {@link #pemsToKeyAndTrustStores}),
     * return a trust manager factory that contains the truststore.
     *
     * @param truststore The truststore to get a trust manager for
     * @return A trust manager factory for the provided truststore
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public static TrustManagerFactory getTrustManagerFactory(KeyStore truststore)
        throws NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException
    {
        final TrustManagerFactory factory;
        if (isFIPS()) {
            factory = TrustManagerFactory.getInstance(PKIX_KEYMANAGER_ALGO, BOUNCYCASTLE_JSSE_PROVIDER);
        } else {
            factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        }
        factory.init(truststore);
        return factory;
    }

    private static TrustManagerFactory getTrustManagerFactory(
            KeyStore trustStore, Reader crls)
        throws NoSuchAlgorithmException, KeyStoreException,
            IOException, CRLException, InvalidAlgorithmParameterException, NoSuchProviderException
    {
        final TrustManagerFactory factory;
        if (isFIPS()) {
            factory = TrustManagerFactory.getInstance(PKIX_KEYMANAGER_ALGO, BOUNCYCASTLE_JSSE_PROVIDER);
        } else {
            factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        }

        if (crls != null) {
            PKIXBuilderParameters pbParams = new PKIXBuilderParameters(
                    trustStore, new X509CertSelector());
            pbParams.setRevocationEnabled(true);
            List<X509CRL> crlsAsList = pemToCRLs(crls);
            pbParams.addCertStore(CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(crlsAsList)));
            factory.init(new CertPathTrustManagerParameters(pbParams));
        }
        else {
            factory.init(trustStore);
        }

        return factory;
    }

    /**
     * Given a KeyManagerFactory and TrustManagerFactory (as generated by
     * {@link #getKeyManagerFactory} and {@link #getTrustManagerFactory}
     * respectively), return an initialized SSLContext.
     *
     * @param kmf KeyManagerFactory The KeyManagerFactory containing
     *                              local private keys
     * @param tmf TrustManagerFactory The TrustManagerFactory containing
     *                                trusted remote certificates
     * @return The configured SSLContext
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     * @throws NoSuchProviderException
     */
    public static SSLContext managerFactoriesToSSLContext(
            KeyManagerFactory kmf,
            TrustManagerFactory tmf)
            throws KeyManagementException, NoSuchAlgorithmException, NoSuchProviderException
    {
        final SSLContext context;
        if (isFIPS()) {
            context = SSLContext.getInstance(TLS_PROTOCOL, BOUNCYCASTLE_JSSE_PROVIDER);
        } else {
            context = SSLContext.getInstance(TLS_PROTOCOL);
        }
        context.init(kmf != null ? kmf.getKeyManagers() : null,
                tmf.getTrustManagers(), null);
        return context;
    }

    /**
     * Given PEM readers for a certificate, private key, and CA certificate,
     * create an in-memory SSL context initialized with a keystore/truststore
     * generated from the provided certificates and key.
     *
     * @param cert Reader for PEM-encoded stream with the certificate
     * @param privateKey Reader for PEM-encoded stream with the corresponding
     *                   private key
     * @param caCert Reader for PEM-encoded stream with the CA certificate
     * @return The configured SSLContext
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     * @throws UnrecoverableKeyException
     */
    public static SSLContext pemsToSSLContext(Reader cert,
                                              Reader privateKey,
                                              Reader caCert)
        throws KeyStoreException, CertificateException, IOException,
            NoSuchAlgorithmException, KeyManagementException,
            UnrecoverableKeyException, NoSuchProviderException
    {
        Map<String, Object> stores = pemsToKeyAndTrustStores(cert, privateKey, caCert);
        KeyStore trustStore = (KeyStore) stores.get("truststore");
        KeyManagerFactory kmf = getKeyManagerFactory(stores);
        TrustManagerFactory tmf = getTrustManagerFactory(trustStore);
        return managerFactoriesToSSLContext(kmf, tmf);
    }

    /**
     * Given PEM readers for a certificate, private key, CA certificate, and,
     * optionally, CRLs, create an in-memory SSL context initialized with a
     * keystore/truststore generated from the provided certificates and key
     * and enabled for revocation checking against the CRLs.
     *
     * @param cert Reader for PEM-encoded stream with the certificate
     * @param privateKey Reader for PEM-encoded stream with the corresponding
     *                   private key
     * @param caCert Reader for PEM-encoded stream with the CA certificate
     * @param crls Reader for stream with one or more PEM-encoded CRLs
     * @return The configured SSLContext
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     * @throws UnrecoverableKeyException
     * @throws CRLException
     * @throws InvalidAlgorithmParameterException
     */
    public static SSLContext pemsToSSLContext(Reader cert,
                                              Reader privateKey,
                                              Reader caCert,
                                              Reader crls)
        throws KeyStoreException, CertificateException, IOException,
            NoSuchAlgorithmException, KeyManagementException,
            UnrecoverableKeyException, CRLException,
            InvalidAlgorithmParameterException, NoSuchProviderException
    {
        Map<String, Object> stores = pemsToKeyAndTrustStores(cert, privateKey, caCert);
        KeyStore trustStore = (KeyStore) stores.get("truststore");
        KeyManagerFactory kmf = getKeyManagerFactory(stores);
        TrustManagerFactory tmf = getTrustManagerFactory(trustStore, crls);
        return managerFactoriesToSSLContext(kmf, tmf);
    }

    private static KeyStore certsToTrustStore(List<X509Certificate> certs)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = createKeyStore();
        return associateCertsFromList(trustStore, "CA Certificate", certs);
    }

    private static KeyStore caCertPemToTrustStore(Reader caCert)
        throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException
    {
        KeyStore trustStore = createKeyStore();
        return associateCertsFromReader(trustStore, "CA Certificate", caCert);
    }

    /**
     * Given a PEM reader for a CA certificate, create an in-memory SSL context
     * initialized with a truststore generated from the CA certificate.  This
     * SSLContext can be used for SSL clients that are connecting to a server
     * with a custom CA, but which do not need to present a client cert to the
     * server.
     *
     * @param caCert Reader for PEM-encoded stream with the CA certificate
     * @return The configured SSLContext
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws KeyManagementException
     */
    public static SSLContext caCertPemToSSLContext(Reader caCert)
        throws CertificateException, NoSuchAlgorithmException, KeyStoreException,
                IOException, KeyManagementException, NoSuchProviderException
    {
        KeyStore trustStore = caCertPemToTrustStore(caCert);
        TrustManagerFactory tmf = getTrustManagerFactory(trustStore);
        return managerFactoriesToSSLContext(null, tmf);
    }

    /**
     * Given a PEM reader for a CA certificate and a reader for CRLs, create an
     * in-memory SSL context initialized with a truststore generated from the CA
     * certificate and enabled for revocation checking against the CRLs.  This
     * SSLContext can be used for SSL clients that are connecting to a server
     * with a custom CA, but which do not need to present a client cert to the
     * server.
     *
     * @param caCert Reader for PEM-encoded stream with the CA certificate
     * @param crls Reader for stream with one or more PEM-encoded CRLs
     * @return The configured SSLContext
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws KeyManagementException
     * @throws CRLException
     * @throws InvalidAlgorithmParameterException
     */
    public static SSLContext caCertAndCrlPemsToSSLContext(Reader caCert,
                                                          Reader crls)
        throws CertificateException, NoSuchAlgorithmException, KeyStoreException,
            IOException, KeyManagementException, CRLException,
            InvalidAlgorithmParameterException, NoSuchProviderException
    {
        KeyStore trustStore = caCertPemToTrustStore(caCert);
        TrustManagerFactory tmf = getTrustManagerFactory(trustStore, crls);
        return managerFactoriesToSSLContext(null, tmf);
    }

    /**
     * Returns the CN from an X500Principal object.
     *
     * @param principal The X500Principal object
     * @return String representation of the CN extracted from the X500Principal.
     */
    public static String getCnFromX500Principal(X500Principal principal) {
        return getCommonNameFromX500Name(principal.getName());
    }

    /**
     * Returns the Subject from an X509Certificate object.
     *
     * @param certificate The X509Certificate object
     * @return String representation of the Subject extracted from the X509Certificate.
     */
    public static String getSubjectFromX509Certificate(X509Certificate certificate) {
        byte[] encodedName = certificate.getSubjectX500Principal().getEncoded();
        X500Name x500Name = X500Name.getInstance(encodedName);
        return BCStyle.INSTANCE.toString(x500Name);
    }

    /**
     * Gets the public key object from a PKCS10CertificationRequest.
     *
     * @param csr A Bouncy Castle certificate request.
     * @return The PublicKey stored in certification request.
     * @throws IOException
     */
    public static PublicKey getPublicKey(PKCS10CertificationRequest csr)
            throws IOException
    {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        return converter.getPublicKey(csr.getSubjectPublicKeyInfo());
    }

    /**
     * Given a Java key pair, return the public key.
     *
     * @param keyPair Java KeyPair object
     * @return The public key half of the key pair.
     */
    public static PublicKey getPublicKey(KeyPair keyPair) {
        return keyPair.getPublic();
    }

    /**
     * Given a Java key pair, return the private key.
     *
     * @param keyPair Java KeyPair object.
     * @return The private key half of the key pair.
     */
    public static PrivateKey getPrivateKey(KeyPair keyPair) {
        return keyPair.getPrivate();
    }

    /**
     * Get the serial number from a certificate.
     *
     * @param cert The X509Certificate
     * @return The certificate's serial number
     */
    public static BigInteger getSerialNumber(X509Certificate cert) {
        return cert.getSerialNumber();
    }

    /**
     * Given a list of attribute names followed by their values, construct an
     * X.500 DN string. For example, if the list ["cn", "common", "o", org"] is
     * passed in then the DN string "CN=common,O=org" is returned.
     *
     * @param rdnPairs A list of attribute and value pairs.
     * @return A X.500 DN string constructed from the given map.
     * @throws IllegalArgumentException If an invalid attribute name is found.
     */
    public static String x500Name(List<String> rdnPairs) {
        if ((rdnPairs.size() % 2) != 0) {
            throw new IllegalArgumentException(
                    "The RDN pairs list must contain an even number of elements.");
        }

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        for (int i=0; i < rdnPairs.size(); i++) {
            String attr = rdnPairs.get(i);
            i++;
            String val = rdnPairs.get(i);

            builder.addRDN(BCStyle.INSTANCE.attrNameToOID(attr), val);
        }

        return builder.build().toString();
    }

    /**
     * Create an RDN which contains the given common name.
     *
     * @param commonName Common name string
     * @return The RDN form of the common name.
     */
    public static String x500NameCn(String commonName) {
        return new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build().toString();
    }

    /**
     * Does the given CSR have a valid signature on it?
     * i.e., was it signed by the private key corresponding to the public key
     * included in the CSR?
     *
     * @param csr The certificate request.
     * @return {@code true} if the CSR has a valid signature, {@code false} otherwise.
     *
     * @throws OperatorCreationException
     * @throws PKCSException
     */
    public static boolean isSignatureValid(PKCS10CertificationRequest csr)
            throws OperatorCreationException, PKCSException
    {
        // Implementation references:
        //  http://www.bouncycastle.org/wiki/display/JA1/BC+Version+2+APIs#BCVersion2APIs-VerifyingaSignature
        //  http://stackoverflow.com/questions/3711754/why-java-security-nosuchproviderexception-no-such-provider-bc
        JcaContentVerifierProviderBuilder builder;
        try {
            Class<?> providerClass = getProviderClass();
            Constructor<?> ctor = providerClass.getConstructor();
            builder = new JcaContentVerifierProviderBuilder().setProvider((Provider)ctor.newInstance());
        } catch(ClassNotFoundException | NoSuchMethodException | InstantiationException |
                IllegalAccessException | InvocationTargetException ex) {
            throw new OperatorCreationException("unable to find suitable provider!", ex);
        }
        try {
            return csr.isSignatureValid(builder.build(csr.getSubjectPublicKeyInfo()));
        } catch(RuntimeOperatorException roe) {
            // in bc-fips, a bad signature generates an exception that isn't generated in the
            // non-FIPS version.
            // specifically:
            // org.bouncycastle.operator.RuntimeOperatorException: exception obtaining signature:
            // org.bouncycastle.crypto.InvalidSignatureException: Unable to process signature: block incorrect
            // Caused by: java.security.SignatureException: org.bouncycastle.crypto.InvalidSignatureException: Unable to
            // process signature: block incorrect
            Throwable cause = roe.getCause();
            if(cause != null && cause.getClass().isAssignableFrom(SignatureException.class)) {
                return false;
            } else {
                throw roe;
            }
        }
    }

    /**
     * Hash the certificate with the digest algorithm and encode the result as a hex string.
     * The digest algorithm is expected to be one of SHA-1, SHA-256, or SHA-512.
     *
     * @param cert The certificate to hash.
     * @param digestAlgorithm The hash algorithm to use.
     * @return The hex string form of the hashed certificate.
     * @throws CertificateEncodingException
     */
    public static String getFingerprint(X509Certificate cert, String digestAlgorithm)
        throws CertificateEncodingException
    {
        return getFingerprint(cert.getEncoded(), digestAlgorithm);
    }

    /**
     * Hash the CSR with the digest algorithm and encode the result as a hex string.
     * The digest algorithm is expected to be one of SHA-1, SHA-256, or SHA-512.
     *
     * @param csr The certificate signing request to hash.
     * @param digestAlgorithm The hash algorithm to use.
     * @return The hex string form of the hashed certificate signing request.
     * @throws IOException
     */
    public static String getFingerprint(PKCS10CertificationRequest csr, String digestAlgorithm)
        throws IOException
    {
        return getFingerprint(csr.getEncoded(), digestAlgorithm);
    }

    private static String getFingerprint(byte[] bytes, String digestAlgorithm) {
        MessageDigest digest = DigestUtils.getDigest(digestAlgorithm);
        return Hex.encodeHexString(digest.digest(bytes));
    }

    /***
     * Get the number of seconds between when a CRL is generated and when it will expire.
     * @return
     */
    public static int getCrlLifetimeSeconds() {
        return crlLifetimeSeconds;
    }

    /***
     * set the number of seconds after the generation time for a CRL before it will expire.
     * @param seconds
     */
    public static void setCrlLifetimeSeconds(int seconds) {
        crlLifetimeSeconds = seconds;
    }
}
