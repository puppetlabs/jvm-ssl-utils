package com.puppetlabs.ssl_utils.test;

import com.puppetlabs.ssl_utils.SSLUtils;

import org.apache.commons.io.FileUtils;
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
            OperatorCreationException, CertificateException, KeyStoreException, SignatureException, InvalidKeyException {
        this.sslDir = PathUtils.concat(confDir, "ssl");
        this.masterCertname = masterCertname;

        this.caX500Name = SSLUtils.x500NameCn("Puppet CA: " + masterCertname);

        this.caPublicKeyPath  = PathUtils.concat(sslDir, PATH_CA_PUBLIC_KEY);
        this.caPrivateKeyPath = PathUtils.concat(sslDir, PATH_CA_PRIVATE_KEY);
        this.caCertPath       = PathUtils.concat(sslDir, PATH_CA_CERT);
        this.caCrlPath        = PathUtils.concat(sslDir, PATH_CA_CRL);

        this.masterPublicKeyPath  = PathUtils.concat(sslDir, PATH_HOST_PUBLIC_KEYS, this.masterCertname + ".pem");
        this.masterPrivateKeyPath = PathUtils.concat(sslDir, PATH_HOST_PRIVATE_KEYS, this.masterCertname + ".pem");
        this.masterCertPath       = getHostCertPath(this.masterCertname);

        initializeCACert();

        this.caPrivateKey = SSLUtils.pemToPrivateKey(new FileReader(this.caPrivateKeyPath));

        initializeMasterCert();

        // Save pems to keystore
        KeyStore ks = SSLUtils.createKeyStore();
        String keystorePassword = "puppet";
        X509Certificate caCert = SSLUtils.pemToCerts(new FileReader(this.caCertPath)).get(0);
        X509Certificate hostCert = SSLUtils.pemToCerts(new FileReader(this.masterCertPath)).get(0);
        PrivateKey hostPrivateKey = SSLUtils.pemToPrivateKey(new FileReader(this.masterPrivateKeyPath));
        SSLUtils.associateCert(ks, "ca-cert-alias", caCert);
        SSLUtils.associateCert(ks, "ca-cert-alias", hostCert);
        SSLUtils.associatePrivateKey(ks, "key-alias", hostPrivateKey, keystorePassword, hostCert);
    }

    public X509Certificate signCertificateRequest(String certname, PKCS10CertificationRequest certRequest)
            throws IOException, OperatorCreationException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // TODO: we are just autosigning here, never saving the CSR to disk.
        X509Certificate cert = SSLUtils.signCertificate(
                caX500Name,
                caPrivateKey,
                nextSerial(),
                this.notBefore, this.notAfter,
                certRequest.getSubject().toString(),
                SSLUtils.getPublicKey(certRequest),
                null);

        SSLUtils.writeToPEM(cert, new FileWriter(getHostCertPath(certname)));
        return cert;
    }

    private void initializeCACert()
            throws NoSuchProviderException, NoSuchAlgorithmException, IOException,
            OperatorCreationException, CRLException, CertificateException, SignatureException, InvalidKeyException {

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

        KeyPair caKeyPair = SSLUtils.generateKeyPair();
        SSLUtils.writeToPEM(caKeyPair.getPublic(), new FileWriter(this.caPublicKeyPath));
        SSLUtils.writeToPEM(caKeyPair.getPrivate(), new FileWriter(this.caPrivateKeyPath));

        PKCS10CertificationRequest caCertReq = SSLUtils.generateCertificateRequest(caKeyPair, this.caX500Name, null);
        X509Certificate caCert = SSLUtils.signCertificate(
                caX500Name,
                caKeyPair.getPrivate(),
                nextSerial(),
                this.notBefore,
                this.notAfter,
                caCertReq.getSubject().toString(),
                SSLUtils.getPublicKey(caCertReq),
                null);
        SSLUtils.writeToPEM(caCert, new FileWriter(this.caCertPath));

        FileUtils.copyFile(new File(this.caCertPath), new File(getHostCertPath("ca")));

        X509CRL caCrl = SSLUtils.generateCRL(caCert.getIssuerX500Principal(), caKeyPair.getPrivate(), caKeyPair.getPublic());
        SSLUtils.writeToPEM(caCrl, new FileWriter(this.caCrlPath));
    }

    private String getHostCertPath(String hostCertName) {
        return PathUtils.concat(this.sslDir, PATH_HOST_CERTS, hostCertName + ".pem");
    }

    private void initializeMasterCert()
            throws IOException, NoSuchProviderException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, SignatureException, InvalidKeyException {

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

        KeyPair masterKeyPair = SSLUtils.generateKeyPair();
        SSLUtils.writeToPEM(masterKeyPair.getPublic(), new FileWriter(masterPublicKeyPath));
        SSLUtils.writeToPEM(masterKeyPair.getPrivate(), new FileWriter(masterPrivateKeyPath));

        String masterX500Name = SSLUtils.x500NameCn(masterCertname);

        X509Certificate caCert = SSLUtils.signCertificate(
                caX500Name,
                caPrivateKey,
                nextSerial(),
                notBefore, notAfter,
                masterX500Name,
                SSLUtils.getPublicKey(masterKeyPair),
                null);

        SSLUtils.writeToPEM(caCert, new FileWriter(masterCertPath));
    }

    private static BigInteger nextSerial() {
        // TODO: this needs to be able to persist between runs.
        int val = nextSerialNum.getAndIncrement();
        return BigInteger.valueOf(val);
    }
}
