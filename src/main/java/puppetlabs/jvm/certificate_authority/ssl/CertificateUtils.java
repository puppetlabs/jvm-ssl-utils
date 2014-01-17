package puppetlabs.jvm.certificate_authority.ssl;

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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
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

public class CertificateUtils {


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // TODO: the exception handling in this class is terrible; should be catching
    //  most of these and raising a more general PuppetCert exception
    //  or similar


    public static KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
//        keyGen.initialize(4096);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static X500Name generateX500Name(String commonName) {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.CN, commonName);

        return x500NameBuilder.build();
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
                        setProvider(BouncyCastleProvider.PROVIDER_NAME).
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
        signerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner signer = signerBuilder.build(issuerPrivateKey);

        X509CertificateHolder holder = builder.build(signer);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return converter.getCertificate(holder);
    }


    public static X509CRL generateCRL(X500Principal issuer,
                                       PrivateKey issuerPrivateKey)
            throws CRLException, OperatorCreationException {

        Date issueDate = DateTime.now().toDate();
        Date nextUpdate = DateTime.now().plusYears(100).toDate();

        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(issuer, issueDate);

        crlGen.setNextUpdate(nextUpdate);

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        signerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner signer = signerBuilder.build(issuerPrivateKey);

        X509CRLHolder crlHolder = crlGen.build(signer);
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return converter.getCRL(crlHolder);
    }


    public static KeyStore pemsToJavaKeystore(String caCertPem, String hostCertPem, String hostPrivateKeyPem, String password) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        PEMReader reader;

        reader = new PEMReader(new InputStreamReader(
                new FileInputStream(caCertPem)));
        X509Certificate ca_cert = (X509Certificate)reader.readObject();

        reader = new PEMReader(new InputStreamReader(
                new FileInputStream(hostCertPem)));
        X509Certificate cert = (X509Certificate)reader.readObject();

        reader = new PEMReader(new InputStreamReader(
                new FileInputStream(hostPrivateKeyPem)));
        KeyPair keyPair = (KeyPair)reader.readObject();

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);
        keystore.setCertificateEntry("ca-cert-alias", ca_cert);
        keystore.setCertificateEntry("cert-alias", cert);
        keystore.setKeyEntry("key-alias", keyPair.getPrivate(),
                password.toCharArray(), new Certificate[] {cert});
        return keystore;
    }


    // TODO: It really sucks that the most specific type we can use
    //  here is 'Object'.
    public static void saveToPEM(Object pemObject, String filePath) throws IOException {
        PEMWriter pemWriter = new PEMWriter(new FileWriter(filePath));
        pemWriter.writeObject(pemObject);
        pemWriter.flush();
    }

    public static PrivateKey readPrivateKey(Reader keyReader) throws IOException {
        PEMReader reader = new PEMReader(keyReader);
        return ((KeyPair) reader.readObject()).getPrivate();
    }


    public static PKCS10CertificationRequest readCertificateRequest(Reader certReqReader) throws IOException {
        PEMReader reader = new PEMReader(certReqReader);
        return new PKCS10CertificationRequest(
            ((org.bouncycastle.jce.PKCS10CertificationRequest) reader.readObject()).getEncoded());
    }



}
