package com.puppetlabs.certificate_authority;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.joda.time.DateTime;
import org.joda.time.Period;
import sun.security.x509.X509Key;

import javax.security.auth.x500.X500Principal;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLContext;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.math.BigInteger;

import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.util.ListIterator;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.UUID;

public class CertificateAuthority {

    /**
     * The default key length to use when generating a keypair.
     */
    public static final int DEFAULT_KEY_LENGTH = 4096;

    /**
     * Create new public & private keys with length 4096.
     *
     * @return A new pair of public & private keys
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @see #generateKeyPair(int)
     */
    public static KeyPair generateKeyPair()
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        return generateKeyPair(DEFAULT_KEY_LENGTH);
    }

    /**
     * Create new public & private keys of the provided length.
     *
     * @return A new pair of public & private keys
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @see #generateKeyPair()
     */
    public static KeyPair generateKeyPair(int keyLength)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keyLength);
        return keyGen.generateKeyPair();
    }

    /**
     * Given an X500Name, return the common name from it.
     *
     * @param x500Name The X500 name string to extract from
     * @return The common name from the X500Name
     */
    public static String getCommonNameFromX500Name(String x500Name) {
        return new X500Name(x500Name).getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
    }

    /**
     * Given the subject's keypair and name, create and return a certificate signing request (CSR).
     * If the extensions parameter is not null and is a list of size great than 0, they will be
     * added to this request.
     *
     * @param keyPair The subject's public and private keys.
     * @param subjectDN The subject's CN.
     * @param extensions Extensions to add to this cert request.
     * @return A request to certify the provided subject
     * @throws IOException
     * @throws OperatorCreationException
     * @see #generateKeyPair
     * @see #signCertificateRequest
     */
    public static PKCS10CertificationRequest generateCertificateRequest(KeyPair keyPair, String subjectDN,
        List<Map<String, Object>> extensions)
        throws IOException, OperatorCreationException
    {
        // TODO: the puppet code sets a property "version=0" on the request object
        // here; can't figure out how to do that at the moment.  Not sure if it's needed.
        PKCS10CertificationRequestBuilder requestBuilder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDN), keyPair.getPublic());

        if ((extensions != null) && (extensions.size() > 0)) {
            Extensions parsedExts = ExtensionsUtils.getExtensionsObjFromMap(extensions);

            requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                                        new DERSet(parsedExts));
        }

        return requestBuilder.build(
                new JcaContentSignerBuilder("SHA1withRSA").
                        build(keyPair.getPrivate()));
    }

    /**
     * Given a certificate signing request and certificate authority
     * information, sign the request and return the signed certificate. If
     * extensions is not null, then all extensions in the list will be written
     * to the new signed certificate. The maps in the extensions list will have
     * the same form as ExtensionsUtils.getExtensionsList().
     *
     * @param certReq The signing request
     * @param issuer The certificate authority's name
     * @param serialNum An arbitrary serial number
     * @param issuerPrivateKey The certificate authority's private key
     * @param extensions A list of X509 extensions to sign into the certificate.
     * @return A signed certificate for the subject
     * @throws OperatorCreationException
     * @throws CertificateException
     * @throws CertIOException
     * @see #generateCertificateRequest
     */
    public static X509Certificate signCertificateRequest(PKCS10CertificationRequest certReq,
                                                         X500Name issuer,
                                                         BigInteger serialNum,
                                                         PrivateKey issuerPrivateKey,
                                                         List<Map<String, Object>> extensions)
            throws OperatorCreationException, CertificateException, IOException {
        // Make the certificate valid as of yesterday, because so many people's
        // clocks are out of sync.  This gives one more day of validity than people
        // might expect, but is better than making every person who has a messed up
        // clock fail, and better than having every cert we generate expire a day
        // before the user expected it to when they asked for "one year".
        DateTime notBefore = DateTime.now().minus(Period.days(1));
        DateTime notAfter = DateTime.now().plus(Period.years(5));

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuer,
                serialNum,
                notBefore.toDate(),
                notAfter.toDate(),
                certReq.getSubject(),
                certReq.getSubjectPublicKeyInfo());

        Extensions bcExtensions = ExtensionsUtils.getExtensionsObjFromMap(extensions);
        if (extensions != null) {
            for (ASN1ObjectIdentifier oid : bcExtensions.getNonCriticalExtensionOIDs()) {
                builder.addExtension(oid, false, bcExtensions.getExtensionParsedValue(oid));
            }

            for (ASN1ObjectIdentifier oid : bcExtensions.getCriticalExtensionOIDs()) {
                builder.addExtension(oid, true, bcExtensions.getExtensionParsedValue(oid));
            }
        }

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256WithRSA");
        ContentSigner signer = signerBuilder.build(issuerPrivateKey);

        X509CertificateHolder holder = builder.build(signer);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        return converter.getCertificate(holder);
    }

    /**
     * Given certificate authority information, expiration dates, and the
     * subject's name and public key info, create a newly signed certificate.
     * If the extensions parameter is not null then all the maps in the list
     * will be parsed into extensions and written on to the certificate. The
     * extensions
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
     * @see com.puppetlabs.certificate_authority.ExtensionsUtils#getExtensionsObjFromMap(java.util.List)
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
        SubjectPublicKeyInfo pubKeyInfo =
                SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name(issuerDn),
                serialNumber,
                notBefore, notAfter,
                new X500Name(subjectDn),
                pubKeyInfo);

        Extensions bcExtensions = ExtensionsUtils.getExtensionsObjFromMap(extensions);
        if (extensions != null) {
            for (ASN1ObjectIdentifier oid : bcExtensions.getNonCriticalExtensionOIDs()) {
                builder.addExtension(oid, false, bcExtensions.getExtensionParsedValue(oid));
            }

            for (ASN1ObjectIdentifier oid : bcExtensions.getCriticalExtensionOIDs()) {
                builder.addExtension(oid, true, bcExtensions.getExtensionParsedValue(oid));
            }
        }

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256WithRSA");
        ContentSigner signer = signerBuilder.build(issuerPrivateKey);

        X509CertificateHolder holder = builder.build(signer);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        return converter.getCertificate(holder);
    }

    /**
     * Given the certificate authority's principal identifier and private key,
     * create a new certificate revocation list (CRL).
     *
     * @param issuer The certificate authority's identifier
     * @param issuerPrivateKey The certificate authority's private key
     * @return A new certificate revocation list
     * @throws CRLException
     * @throws OperatorCreationException
     */
    public static X509CRL generateCRL(X500Principal issuer, PrivateKey issuerPrivateKey)
        throws CRLException, OperatorCreationException
    {
        Date issueDate = DateTime.now().toDate();
        Date nextUpdate = DateTime.now().plusYears(100).toDate();

        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(issuer, issueDate);

        crlGen.setNextUpdate(nextUpdate);

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = signerBuilder.build(issuerPrivateKey);

        X509CRLHolder crlHolder = crlGen.build(signer);
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        return converter.getCRL(crlHolder);
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

    // ---- PORTED KITCHENSINK FUNCIONS ----

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
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null);
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
        PEMWriter pw = new PEMWriter(writer);
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
        throws IOException, PEMException
    {
        List<Object> objects = pemToObjects(reader);
        List<PrivateKey> results = new ArrayList<PrivateKey>(objects.size());
        for (Object o : objects)
            results.add(objectToPrivateKey(o));
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
            throw new IllegalArgumentException("The PEM stream must contain exactly one public key");
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        return converter.getPublicKey((SubjectPublicKeyInfo) objects.get(0));
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
        ListIterator<X509Certificate> iter = certs.listIterator();
        for (int i = 0; iter.hasNext(); i++)
            associateCert(keystore, prefix + "-" + i, iter.next());
        return keystore;
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
    public static KeyStore associatePrivateKey(KeyStore keystore, String alias, PrivateKey privateKey,
                                               String password, X509Certificate cert)
        throws KeyStoreException
    {
        keystore.setKeyEntry(alias, privateKey, password.toCharArray(), new Certificate[]{cert});
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
    public static KeyStore associatePrivateKeyFromReader(KeyStore keystore, String alias, Reader pemPrivateKey,
                                                         String password, Reader pemCert)
        throws CertificateException, KeyStoreException, IOException
    {
        PrivateKey privateKey = pemToPrivateKey(pemPrivateKey);
        List<X509Certificate> certs = pemToCerts(pemCert);

        if (certs.size() > 1)
            throw new IllegalArgumentException("The PEM stream contains more than one certificate");

        X509Certificate firstCert = certs.get(0);
        return associatePrivateKey(keystore, alias, privateKey, password, firstCert);
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
        throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException
    {
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keystore, password.toCharArray());
        return factory;
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
        throws NoSuchAlgorithmException, KeyStoreException
    {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(truststore);
        return factory;
    }

    /**
     * Given PEM readers for a certificate, private key, and CA certificate, create an
     * in-memory SSL context initialized with a keystore/truststore generated from the
     * provided certificates and key.
     *
     * @param cert Reader for PEM-encoded stream with the certificate
     * @param privateKey Reader for PEM-encoded stream with the corresponding private key
     * @param caCert Reader for PEM-encoded stream with the CA certificate
     * @return The configured SSLContext
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     * @throws UnrecoverableKeyException
     */
    public static SSLContext pemsToSSLContext(Reader cert, Reader privateKey, Reader caCert)
        throws KeyStoreException, CertificateException, IOException,
               NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException
    {
        Map<String, Object> stores = pemsToKeyAndTrustStores(cert, privateKey, caCert);
        KeyStore keystore = (KeyStore) stores.get("keystore");
        String password = (String) stores.get("keystore-pw");
        KeyStore truststore = (KeyStore) stores.get("truststore");
        KeyManagerFactory kmf = getKeyManagerFactory(keystore, password);
        TrustManagerFactory tmf = getTrustManagerFactory(truststore);
        SSLContext context = SSLContext.getInstance("SSL");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
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
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     */
    public static SSLContext caCertPemToSSLContext(Reader caCert)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException,
                    IOException, KeyManagementException {
        KeyStore truststore = createKeyStore();
        associateCertsFromReader(truststore, "CA Certificate", caCert);

        TrustManagerFactory tmf = getTrustManagerFactory(truststore);
        SSLContext context = SSLContext.getInstance("SSL");
        context.init(null, tmf.getTrustManagers(), null);
        return context;
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
     * @return The public key half of the key pair.=
     */
    public static PublicKey getPublicKey(KeyPair keyPair) {
        return keyPair.getPublic();
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
}
