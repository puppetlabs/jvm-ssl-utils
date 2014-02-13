package puppetlabs.jvm.certificate_authority;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
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

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.util.ListIterator;

public class CertificateUtils {

    // TODO: the exception handling in this class is terrible; should be catching
    //  most of these and raising a more general PuppetCert exception
    //  or similar

    public static KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // TODO make length configurable
//        keyGen.initialize(4096);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static X500Name generateX500Name(String commonName) {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.CN, commonName);
        return x500NameBuilder.build();
    }

    public static String getCommonNameFromX500Name(X500Name x500Name) {
        return x500Name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
    }

    public static PKCS10CertificationRequest generateCertReq(KeyPair keyPair, X500Name subjectName)
            throws IOException, OperatorCreationException {
        // TODO: the puppet code sets a property "version=0" on the request object
        //  here; can't figure out how to do that at the moment.  Not sure if it's needed.
        PKCS10CertificationRequestBuilder requestBuilder =
                new JcaPKCS10CertificationRequestBuilder(subjectName, keyPair.getPublic());

        // TODO: support DNS ALT names; probably looks something like this:
//        Extensions extensions = new Extensions(new Extension[] {
//                new Extension(X509Extension.subjectAlternativeName, false,
//                        new DEROctetString(
//                                new GeneralNames(new GeneralName[] {
//                                        new GeneralName(GeneralName.dNSName, "foo.bar.com"),
//                                        new GeneralName(GeneralName.dNSName, "bar.baz.com"),
//                                        })))
//        });
//
//        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
//                new DERSet(extensions));

        return requestBuilder.build(
                new JcaContentSignerBuilder("SHA1withRSA").
                        build(keyPair.getPrivate()));
    }

    public static X509Certificate signCertificateRequest(PKCS10CertificationRequest certReq,
                                                          X500Name issuer,
                                                          BigInteger serialNum,
                                                          PrivateKey issuerPrivateKey)
            throws OperatorCreationException, CertificateException {

//        # Make the certificate valid as of yesterday, because so many people's
//        # clocks are out of sync.  This gives one more day of validity than people
//        # might expect, but is better than making every person who has a messed up
//        # clock fail, and better than having every cert we generate expire a day
//        # before the user expected it to when they asked for "one year".
        DateTime notBefore = DateTime.now().minus(Period.days(1));
        DateTime notAfter = DateTime.now().plus(Period.years(5));

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuer,
                serialNum,
                notBefore.toDate(),
                notAfter.toDate(),
                certReq.getSubject(),
                certReq.getSubjectPublicKeyInfo());

        // TODO: add extensions to cert (maps to build_ca_extensions,
        //  build_server_extensions in certificate_factory.rb.
//
//        add_extensions_to(cert, csr, issuer, send(build_extensions))
//

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256WithRSA");
        ContentSigner signer = signerBuilder.build(issuerPrivateKey);

        X509CertificateHolder holder = builder.build(signer);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        return converter.getCertificate(holder);
    }

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

    public static PKCS10CertificationRequest pemToCertificationRequest(Reader reader)
        throws IOException
    {
        List<Object> pemObjects = pemToObjects(reader);
        if (pemObjects.size() > 1)
            throw new IllegalArgumentException("The PEM file " + reader + " contains more than one object");
        return (PKCS10CertificationRequest) pemObjects.get(0);
    }

    // ---- PORTED KITCHENSINK FUNCIONS ----

    public static KeyStore createKeyStore()
        throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null);
        return ks;
    }

    public static List<Object> pemToObjects(Reader reader)
        throws IOException
    {
        PEMParser parser = new PEMParser(reader);
        List<Object> results = new ArrayList<Object>();
        for (Object o = parser.readObject(); o != null; o = parser.readObject())
            results.add(o);
        return results;
    }

    public static void writeToPEM(Object o, Writer writer)
        throws IOException
    {
        PEMWriter pw = new PEMWriter(writer);
        pw.writeObject(o);
        pw.flush();
    }

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

    public static List<PrivateKey> pemToPrivateKeys(Reader reader)
        throws IOException, PEMException
    {
        List<Object> objects = pemToObjects(reader);
        List<PrivateKey> results = new ArrayList<PrivateKey>(objects.size());
        for (Object o : objects)
            results.add(objectToPrivateKey(o));
        return results;
    }

    public static PrivateKey pemToPrivateKey(Reader reader)
        throws IOException
    {
        List<PrivateKey> privateKeys = pemToPrivateKeys(reader);
        if (privateKeys.size() != 1)
            throw new IllegalArgumentException("The PEM file " + reader + " must contain exactly one private key");
        return privateKeys.get(0);
    }

    public static KeyStore associateCert(KeyStore keystore, String alias, X509Certificate cert)
        throws KeyStoreException
    {
        keystore.setCertificateEntry(alias, cert);
        return keystore;
    }

    public static KeyStore associateCertsFromReader(KeyStore keystore, String prefix, Reader pem)
        throws CertificateException, KeyStoreException, IOException
    {
        List<X509Certificate> certs = pemToCerts(pem);
        ListIterator<X509Certificate> iter = certs.listIterator();
        for (int i = 0; iter.hasNext(); i++)
            associateCert(keystore, prefix + "-" + i, iter.next());
        return keystore;
    }

    public static KeyStore associatePrivateKey(KeyStore keystore, String alias, PrivateKey privateKey,
                                               String password, X509Certificate cert)
        throws KeyStoreException
    {
        keystore.setKeyEntry(alias, privateKey, password.toCharArray(), new Certificate[]{cert});
        return keystore;
    }

    public static KeyStore associatePrivateKeyReader(KeyStore keystore, String alias, Reader pemPrivateKey,
                                                     String password, Reader pemCert)
        throws CertificateException, KeyStoreException, IOException
    {
        List<PrivateKey> keys = pemToPrivateKeys(pemPrivateKey);
        List<X509Certificate> certs = pemToCerts(pemCert);

        if (keys.size() > 1)
            throw new IllegalArgumentException("The PEM file " + pemPrivateKey + " contains more than one key");

        if (certs.size() > 1)
            throw new IllegalArgumentException("The PEM file " + pemCert + " contains more than one certificate");

        PrivateKey firstKey = keys.get(0);
        X509Certificate firstCert = certs.get(0);
        return associatePrivateKey(keystore, alias, firstKey, password, firstCert);
    }
}
