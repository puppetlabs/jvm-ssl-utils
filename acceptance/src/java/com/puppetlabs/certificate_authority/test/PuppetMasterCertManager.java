package com.puppetlabs.certificate_authority.test;

import com.puppetlabs.certificate_authority.CertificateAuthority;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.DateTime;
import org.joda.time.Period;
import java.util.Date;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.ArrayList;

public class PuppetMasterCertManager {
    private static final String PATH_CA_PUBLIC_KEY      = "ca/ca_pub.pem";
    private static final String PATH_CA_PRIVATE_KEY     = "ca/ca_key.pem";
    private static final String PATH_CA_CERT            = "ca/ca_crt.pem";
    private static final String PATH_CA_CRL             = "ca/ca_crl.pem";
    private static final String PATH_HOST_PUBLIC_KEYS   = "public_keys";
    private static final String PATH_HOST_PRIVATE_KEYS  = "private_keys";
    private static final String PATH_HOST_CERTS         = "certs";

    private static final AtomicInteger nextSerialNum = new AtomicInteger(1);

    private final String masterCertname;
    private final String sslDir;
    private final String caX500Name;

    private final String caPublicKeyPath;
    private final String caPrivateKeyPath;
    private final String caCertPath;
    private final String caCrlPath;
    private final PrivateKey caPrivateKey;

    private final String masterPublicKeyPath;
    private final String masterPrivateKeyPath;
    private final String masterCertPath;

    private final Date notBefore = DateTime.now().minus(Period.days(1)).toDate();
    private final Date notAfter = DateTime.now().plus(Period.years(5)).toDate();

    // TODO: the exception handling in this class is terrible; should be catching
    //  most of these and raising a more general PuppetCert exception
    //  or similar

    public PuppetMasterCertManager(String confDir, String masterCertname)
            throws IOException, NoSuchProviderException, NoSuchAlgorithmException, CRLException,
                   OperatorCreationException, CertificateException, KeyStoreException
    {
        this.sslDir = PathUtils.concat(confDir, "ssl");
        this.masterCertname = masterCertname;

        this.caX500Name = "CN=" + masterCertname;

        this.caPublicKeyPath  = PathUtils.concat(sslDir, PATH_CA_PUBLIC_KEY);
        this.caPrivateKeyPath = PathUtils.concat(sslDir, PATH_CA_PRIVATE_KEY);
        this.caCertPath       = PathUtils.concat(sslDir, PATH_CA_CERT);
        this.caCrlPath        = PathUtils.concat(sslDir, PATH_CA_CRL);

        this.masterPublicKeyPath  = PathUtils.concat(sslDir, PATH_HOST_PUBLIC_KEYS, this.masterCertname + ".pem");
        this.masterPrivateKeyPath = PathUtils.concat(sslDir, PATH_HOST_PRIVATE_KEYS, this.masterCertname + ".pem");
        this.masterCertPath       = getHostCertPath(this.masterCertname.toString());

        initializeCACert();

        this.caPrivateKey = CertificateAuthority.pemToPrivateKey(new FileReader(this.caPrivateKeyPath));

        initializeMasterCert();

        // Save pems to keystore
        KeyStore ks = CertificateAuthority.createKeyStore();
        String keystorePassword = "puppet";
        X509Certificate caCert = CertificateAuthority.pemToCerts(new FileReader(this.caCertPath)).get(0);
        X509Certificate hostCert = CertificateAuthority.pemToCerts(new FileReader(this.masterCertPath)).get(0);
        PrivateKey hostPrivateKey = CertificateAuthority.pemToPrivateKey(new FileReader(this.masterPrivateKeyPath));
        CertificateAuthority.associateCert(ks, "ca-cert-alias", caCert);
        CertificateAuthority.associateCert(ks, "ca-cert-alias", hostCert);
        CertificateAuthority.associatePrivateKey(ks, "key-alias", hostPrivateKey, keystorePassword, hostCert);
    }

    public X509Certificate signCertificateRequest(String certname, PKCS10CertificationRequest certRequest)
        throws IOException, OperatorCreationException, CertificateException
    {
        // TODO: we are just autosigning here, never saving the CSR to disk.
        X509Certificate cert = CertificateAuthority.signCertificate(
                certRequest.getSubject().toString(),
                caPrivateKey,
                nextSerial(),
                this.notBefore, this.notAfter,
                caX500Name.toString(),
                CertificateAuthority.getPublicKey(certRequest),
                null);

        CertificateAuthority.writeToPEM(cert, new FileWriter(getHostCertPath(certname)));
        return cert;
    }

    private void initializeCACert()
        throws NoSuchProviderException, NoSuchAlgorithmException, IOException,
               OperatorCreationException, CRLException, CertificateException
    {

        if (new File(this.caPublicKeyPath).exists() &&
            new File(this.caPrivateKeyPath).exists() &&
            new File(this.caCertPath).exists() &&
            new File(this.caCrlPath).exists()) {
            return;
        }

        for (String filePath : new String[] {
                this.caPublicKeyPath, this.caPrivateKeyPath,
                this.caCertPath, this.caCrlPath }) {
            FileUtils.forceMkdir(new File(filePath).getParentFile());
        }

        KeyPair caKeyPair = CertificateAuthority.generateKeyPair();
        CertificateAuthority.writeToPEM(caKeyPair.getPublic(), new FileWriter(this.caPublicKeyPath));
        CertificateAuthority.writeToPEM(caKeyPair.getPrivate(), new FileWriter(this.caPrivateKeyPath));

        PKCS10CertificationRequest caCertReq = CertificateAuthority.generateCertificateRequest(caKeyPair, this.caX500Name, null);
        X509Certificate caCert = CertificateAuthority.signCertificate(
                caX500Name,
                caKeyPair.getPrivate(),
                nextSerial(),
                this.notBefore,
                this.notAfter,
                caCertReq.getSubject().toString(),
                CertificateAuthority.getPublicKey(caCertReq),
                null);
        CertificateAuthority.writeToPEM(caCert, new FileWriter(this.caCertPath));

        FileUtils.copyFile(new File(this.caCertPath), new File(getHostCertPath("ca")));

        X509CRL caCrl = CertificateAuthority.generateCRL(caCert.getIssuerX500Principal(), caKeyPair.getPrivate());
        CertificateAuthority.writeToPEM(caCrl, new FileWriter(this.caCrlPath));
    }

    private String getHostCertPath(String hostCertName) {
        return PathUtils.concat(this.sslDir, PATH_HOST_CERTS, hostCertName + ".pem");
    }

    private void initializeMasterCert()
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException, OperatorCreationException, CertificateException
    {

        if (new File(masterPublicKeyPath).exists() &&
            new File(masterPrivateKeyPath).exists() &&
            new File(masterCertPath).exists()) {
            return;
        }

        for (String filePath : new String[] {
                this.masterPublicKeyPath, this.masterPrivateKeyPath,
                this.masterCertPath }) {
            FileUtils.forceMkdir(new File(filePath).getParentFile());
        }

        KeyPair masterKeyPair = CertificateAuthority.generateKeyPair();
        CertificateAuthority.writeToPEM(masterKeyPair.getPublic(), new FileWriter(masterPublicKeyPath));
        CertificateAuthority.writeToPEM(masterKeyPair.getPrivate(), new FileWriter(masterPrivateKeyPath));

        String masterX500Name = "CN=" + masterCertname;

        X509Certificate caCert = CertificateAuthority.signCertificate(
                caX500Name.toString(),
                caPrivateKey,
                nextSerial(),
                notBefore, notAfter,
                masterX500Name,
                CertificateAuthority.getPublicKey(masterKeyPair),
                null);

        CertificateAuthority.writeToPEM(caCert, new FileWriter(masterCertPath));
    }

    private static BigInteger nextSerial() {
        // TODO: this needs to be able to persist between runs.
        int val = nextSerialNum.getAndIncrement();
        return BigInteger.valueOf(val);
    }
}
