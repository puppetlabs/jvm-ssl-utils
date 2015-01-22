package com.puppetlabs.ssl_utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Utilities for working with X509 extensions.
 */
public class ExtensionsUtils {

    /**
     * CRLNumber OID 2.5.29.20
     */
    public static final String CRL_NUMBER_OID = Extension.cRLNumber.toString();

    /**
     * AuthorityKeyIdentifier OID 2.5.29.35
     */
    public static final String AUTHORITY_KEY_IDENTIFIER_OID =
        Extension.authorityKeyIdentifier.toString();

    /**
     * SubjectAlternativeName OID 2.5.29.17
     */
    public static final String SUBJECT_ALTERNATIVE_NAME_OID =
        Extension.subjectAlternativeName.toString();

    /**
     * Return true if the given OID is contained within the subtree of parent OID.
     *
     * @param parentOid The OID of the parent tree.
     * @param oid The OID to compare.
     * @return True if OID is a subtree
     */
    public static boolean isSubtreeOf(String parentOid, String oid) {
        if (parentOid.equals(oid)) {
            return false;
        } else {
            return oid.startsWith(parentOid);
        }
    }

    /**
     * Given a Java X509Certificate object, return a list of maps representing
     * all the X509 extensions embedded in the certificate. If no extensions
     * exist on the certificate, then null is returned.
     *
     * @param cert The X509 certificate object.
     * @return A list of maps describing each extensions in the provided
     *         certificate.
     * @throws IOException
     * @throws CertificateEncodingException
     * @see #getExtensionList(Extensions)
     */
    public static List<Map<String, Object>> getExtensionList(X509Certificate cert)
            throws IOException, CertificateEncodingException
    {
        Extensions extensions = getExtensionsFromCert(cert);

        if (extensions != null) {
            return getExtensionList(extensions);
        } else {
            return null;
        }
    }

    /**
     * Given a Java X509CRL object, return a list of maps representing
     * all the X509 extensions embedded in the CRL.  If no extensions
     * exist on the CRL, then null is returned.
     *
     * @param crl The X509 CRL object.
     * @return A list of maps describing each extensions in the provided CRL.
     * @throws IOException
     * @throws CRLException
     * @see #getExtensionList(Extensions)
     */
    public static List<Map<String, Object>> getExtensionList(X509CRL crl)
            throws IOException, CRLException
    {
        Extensions extensions = getExtensionsFromCRL(crl);

        if (extensions != null) {
            return getExtensionList(extensions);
        } else {
            return null;
        }
    }

    /**
     * Given a Bouncy Castle CSR object, return a list of maps representing
     * all the X509 extensions embedded in the CSR. If no extensions exist on
     * the CSR, then null is returned.
     *
     * @param csr The Bouncy Castle CertificationRequest object
     * @return A list of maps describing each extensions in the provided
     *         certificate.
     * @throws IOException
     * @see #getExtensionList(Extensions)
     */
    public static List<Map<String, Object>> getExtensionList(PKCS10CertificationRequest csr)
            throws IOException
    {
        Extensions extensions = getExtensionsFromCSR(csr);

        if (extensions != null) {
            return getExtensionList(extensions);
        } else{
            return null;
        }
    }

    /**
     * Given a Java certificate, get a map containing the value
     * and criticality of the extensions described by the given OID. If the OID
     * is not found in the certificate then null is returned.
     *
     * @param cert The Java X509 certificate object.
     * @param oid The OID of the extension to be found.
     * @return The map containing the extension value and critical flag.
     * @throws IOException
     * @throws CertificateEncodingException
     */
    public static Map<String, Object> getExtension(X509Certificate cert, String oid)
            throws IOException, CertificateEncodingException
    {
        Extensions extensions = getExtensionsFromCert(cert);

        if (extensions != null) {
            return makeExtensionMap(extensions, new ASN1ObjectIdentifier(oid));
        } else {
            return null;
        }
    }

    /**
     * Given a Java X509CRL object, get a map containing the value and
     * criticality of the extensions described by the given OID. If the OID
     * is not found in the CRL, then null is returned. If no extensions exist
     * on the CRL, then null is returned.
     *
     * @param crl The X509 CRL object.
     * @param oid The OID of the extension to be found.
     * @return The map containing the extension value and critical flag.
     * @throws IOException
     * @throws CRLException
     */
    public static Map<String, Object> getExtension(X509CRL crl, String oid)
            throws IOException, CRLException
    {
        Extensions extensions = getExtensionsFromCRL(crl);

        if (extensions != null) {
            return makeExtensionMap(extensions, new ASN1ObjectIdentifier(oid));
        } else {
            return null;
        }
    }

    /**
     * Given a Bouncy Castle CSR, get a map describing an extension value and
     * its criticality from its OID. If the extension is not found then null
     * is returned.
     *
     * @param csr The Bouncy Castle CSR to extract an extension from.
     * @param oid The OID of extension to find.
     * @return A map describing the extension requested by its OID.
     * @throws IOException
     */
    public static Map<String, Object> getExtension(PKCS10CertificationRequest csr, String oid)
            throws IOException
    {
        Extensions extensions = getExtensionsFromCSR(csr);

        if (extensions != null) {
            return makeExtensionMap(extensions, new ASN1ObjectIdentifier(oid));
        } else {
            return null;
        }
    }

    /**
     * Given a list of maps describing extensions, return a map containing
     * the extensions described by the provided OID. Returns null if the OID
     * doesn't exist in the provided list.
     *
     * @param extList A list of extensions returned by getExtensionList().
     * @param oid The OID of the extension to find.
     * @return The map describing the found extension, null if the oid doesn't exist.
     * @see #getExtensionList(org.bouncycastle.asn1.x509.Extensions)
     * @see #getExtensionList(java.security.cert.X509Certificate)
     */
    public static Map<String, Object> getExtension(List<Map<String, Object>> extList,
                                                   String oid)
    {
        for (Map<String, Object> ext: extList) {
            if (ext.get("oid").equals(oid)) {
                return ext;
            }
        }

        return null;
    }

    public static Object getExtensionValue(X509Certificate cert, String oid)
            throws IOException, CertificateEncodingException
    {
        return getExtensionValue(getExtension(cert, oid));
    }

    public static Object getExtensionValue(X509CRL crl, String oid)
            throws IOException, CRLException
    {
        return getExtensionValue(getExtension(crl, oid));
    }

    public static Object getExtensionValue(PKCS10CertificationRequest csr,
                                           String oid)
            throws IOException
    {
        return getExtensionValue(getExtension(csr, oid));
    }

    public static Object getExtensionValue(List<Map<String, Object>> extList,
                                           String oid)
    {
        return getExtensionValue(getExtension(extList, oid));
    }

    public static Object getExtensionValue(Map<String, Object> extMap) {
        if (extMap != null) {
            return extMap.get("value");
        } else {
            return null;
        }
    }

    /**
     * Given a Bouncy Castle Extensions container, return a list of maps
     * representing all the X509 extensions embedded in the certificate.
     *
     * @param exts A Bouncy Castle Extensions container object.
     * @return A list of maps describing each extensions in the provided
     *         certificate.
     * @throws IOException
     */
    private static List<Map<String, Object>> getExtensionList(Extensions exts)
            throws IOException
    {
        List<Map<String, Object>> ret = new ArrayList<Map<String, Object>>();

        for (ASN1ObjectIdentifier oid : exts.getCriticalExtensionOIDs()) {
            ret.add(makeExtensionMap(exts, oid, true));
        }

        for (ASN1ObjectIdentifier oid : exts.getNonCriticalExtensionOIDs()) {
            ret.add(makeExtensionMap(exts, oid, false));
        }

        return ret;
    }

    /**
     * Given an extensions container and an OID, extract the value and
     * criticality flag and return the values in a map. If the extension is not
     * found then null is returned.
     *
     * @param exts The Bouncy Castle extensions container.
     * @param oid The OID of the extension to find.
     * @return A map
     * @throws IOException
     */
    private static Map<String, Object> makeExtensionMap(Extensions exts,
                                                        ASN1ObjectIdentifier oid)
            throws IOException
    {
        boolean critical = Arrays.asList(exts.getCriticalExtensionOIDs()).contains(oid);
        return makeExtensionMap(exts, oid, critical);
    }

    /**
     * Find the X509 Extensions from CSR object. If no extensions
     * attribute is found then null is returned.
     *
     * @param csr The CSR object to extract the Extensions container from.
     * @return An extensions container extracted form the CSR.
     */
    static Extensions getExtensionsFromCSR(PKCS10CertificationRequest csr) {
        Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        for (Attribute attr : attrs) {
            ASN1Set extsAsn1 = attr.getAttrValues();
            if (extsAsn1 != null) {
                ASN1Encodable extObj = extsAsn1.getObjectAt(0);

                if (extObj instanceof Extensions) {
                    return (Extensions)extObj;
                } else if (extObj instanceof DERSequence) {
                    return Extensions.getInstance(extObj);
                }
            }
        }

        return null;
    }

    /**
     * Given a list of maps which represent Extensions, produce a Bouncy Castle
     * Extensions object which contains each extension parsed into Bouncy Castle
     * Extension objects.
     *
     * @return The results Extensions container.
     * @see #parseExtensionObject(java.util.Map)
     */
    static Extensions getExtensionsObjFromMap(List<Map<String,Object>> extMapsList)
            throws IOException, OperatorCreationException {
        if ((extMapsList != null) && (extMapsList.size() > 0)) {
            List<Extension> ret = new ArrayList<Extension>();
            for (Map<String, Object> extObj : extMapsList) {
                ret.add(parseExtensionObject(extObj));
            }

            return new Extensions(ret.toArray(new Extension[ret.size()]));
        } else {
            return null;
        }
    }

    /**
     * Provided a map which describes an X509 extension, parse it into a
     * Bouncy Castle Extension object.
     *
     * @param extMap Map describing an extension.
     * @return A parsed Extension object.
     * @throws IOException
     */
    @SuppressWarnings("unchecked")
    static Extension parseExtensionObject(Map<String, Object> extMap)
            throws IOException, OperatorCreationException
    {
        String oidString = (String)extMap.get("oid");
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidString);
        Boolean isCritical = (Boolean) extMap.get("critical");

        if (oid.equals(Extension.subjectAlternativeName) ||
                oid.equals(Extension.issuerAlternativeName)) {
            @SuppressWarnings("unchecked")
            Map<String, List<String>> val = (Map<String, List<String>>) extMap.get("value");
            return new Extension(oid, isCritical, new DEROctetString(mapToGeneralNames(val)));
        } else if (oid.equals(MiscObjectIdentifiers.netscapeCertComment)) {
            DERIA5String ia5Str = new DERIA5String((String) extMap.get("value"));
            return new Extension(oid, isCritical, new DEROctetString(ia5Str));
        } else if (oid.equals(Extension.keyUsage)) {
            Set<String> val = (Set<String>) extMap.get("value");
            return new Extension(oid, isCritical, new DEROctetString(setToKeyUsage(val)));
        } else if (oid.equals(Extension.extendedKeyUsage)) {
            List<String> list = (List<String>) extMap.get("value");
            return new Extension(oid, isCritical, new DEROctetString(listToExtendedKeyUsage(list)));
        } else if (oid.equals(Extension.basicConstraints)) {
            Map<String, Object> val = (Map<String, Object>) extMap.get("value");
            return new Extension(oid, isCritical, new DEROctetString(mapToBasicConstraints(val)));
        } else if (oid.equals(Extension.subjectKeyIdentifier)) {
            PublicKey pubKey = (PublicKey) extMap.get("value");
            return new Extension(oid, isCritical, new DEROctetString(publicKeyToSubjectKeyIdentifier(pubKey)));
        } else if (oid.equals(Extension.authorityKeyIdentifier)) {
            Map<String, Object> val = (Map<String, Object>) extMap.get("value");
            return new Extension(oid, isCritical,
                    new DEROctetString(mapToAuthorityKeyIdentifier(val)));
        } else if (oid.equals(Extension.cRLNumber)) {
            BigInteger number = (BigInteger) extMap.get("value");
            return new Extension(oid, false, new DEROctetString(
                    new CRLNumber(number)));
        } else {
            // If the OID isn't recognized, then just parse the value as a string
            String value = (String) extMap.get("value");
            return new Extension(oid, isCritical, new DEROctetString(value.getBytes()));
        }
    }

    /**
     * Get a Bouncy Castle Extensions container from a Java X509 certificate
     * object. If no extensions are found then null is returned.
     *
     * @param cert  The Java X509 certificate object.
     * @return A Bouncy Castle Extensions container object extracted from the
     *         certificate.
     * @throws CertificateEncodingException
     * @throws IOException
     */
    private static Extensions getExtensionsFromCert(X509Certificate cert)
            throws CertificateEncodingException, IOException
    {
        return new X509CertificateHolder(cert.getEncoded()).getExtensions();
    }

    /**
     * Get a Bouncy Castle Extensions container from a Java X509 CRL
     * object. If no extensions are found then null is returned.
     *
     * @param crl  The Java X509 CRL object.
     * @return A Bouncy Castle Extensions container object extracted from the
     *         CRL.
     * @throws CRLException
     * @throws IOException
     */
    private static Extensions getExtensionsFromCRL(X509CRL crl)
            throws CRLException, IOException
    {
        return new X509CRLHolder(crl.getEncoded()).getExtensions();
    }

    /**
     * Given an Extensions container, an OID, and a critical flag, create a map
     * of this extension's data with the following keys:
     *
     *   - "oid"      : The OID of the extensions
     *   - "value"    : A String, or list of Strings of this OID's data
     *   - "critical" : A bool set to true if this extensions is critical,
     *                  false if it isn't.
     *
     * If the given OID doesn't exist in the extensions container then null is
     * returned.
     *
     * @param exts A Bouncy Castle Extensions container containing the provided OID
     * @param oid The OID of the extension to create the map for.
     * @param critical True if this extension is critical, false if it isn't.
     * @return A map representing the extension with the given OID which exists
     *         in the provided Extensions container.
     * @throws IOException
     */
    private static Map<String, Object> makeExtensionMap(Extensions exts,
                                                        ASN1ObjectIdentifier oid,
                                                        boolean critical)
            throws IOException
    {
        Extension ext = exts.getExtension(oid);
        if (ext != null) {
            byte[] extensionData = ext.getExtnValue().getOctets();
            ASN1Object asn1Value = binaryToASN1Object(oid, extensionData);

            HashMap<String, Object> ret = new HashMap<String, Object>();
            ret.put("oid", oid.getId());
            ret.put("critical", critical);
            ret.put("value", asn1ObjToObj(asn1Value));

            return ret;
        } else {
            return null;
        }
    }

    /**
     * Convert a chunk of binary data into the Bouncy Castle ASN1 data structure
     * which represents the data it contains accord to its OID. I've searched
     * all over the BouncyCastle API and I can't seem to find this mapping
     * defined anywhere, so I've created it here.
     *
     * @param oid   The extension OID.
     * @param data  The binary data value of the extension with the given OID.
     * @return An ASN1Object which contains the data described by the
     *         provided OID.
     * @throws IOException
     */
    private static ASN1Object binaryToASN1Object(ASN1ObjectIdentifier oid,
                                                 byte[] data)
            throws IOException
    {
        if (oid.equals(Extension.subjectAlternativeName) ||
            oid.equals(Extension.issuerAlternativeName))
        {
            return GeneralNames.getInstance(data);
        } else if (oid.equals(Extension.authorityKeyIdentifier)) {
            return AuthorityKeyIdentifier.getInstance(data);
        } else if (oid.equals(Extension.subjectKeyIdentifier)) {
            return SubjectKeyIdentifier.getInstance(data);
        } else if (oid.equals(Extension.basicConstraints)) {
            return BasicConstraints.getInstance(data);
        } else if (oid.equals(Extension.keyUsage)) {
            DERBitString bs = (DERBitString) ASN1Primitive.fromByteArray(data);
            return KeyUsage.getInstance(bs);
        } else if (oid.equals(Extension.extendedKeyUsage)) {
            return ExtendedKeyUsage.getInstance(data);
        } else if (oid.equals(MiscObjectIdentifiers.netscapeCertComment)) {
            try {
                return ASN1Primitive.fromByteArray(data);
            } catch (EOFException e) {
                // Sometimes the comment field is not wrapped in an IA5String
                return new DERPrintableString(new String(data, "UTF8"));
            }
        } else if (oid.equals(Extension.cRLNumber)) {
            return CRLNumber.getInstance(data);
        } else {
            // Most extensions are a simple string value.
            return new DERPrintableString(new String(data, "UTF8"));
        }
    }

    /**
     * Convert a Bouncy Castle ASN1Object into a Java data structure, which
     * will generally be in the form of a string, map, list or combination thereof.
     * If this method can't determine a method of converting the ASN1 object then
     * the raw byte array is returned.
     *
     * @param asn1Prim The ASN1 object to
     * @return A Java data structure which represents the provided ASN1Object.
     * @throws IOException
     */
    private static Object asn1ObjToObj(ASN1Encodable asn1Prim)
            throws IOException
    {
        if (asn1Prim instanceof GeneralNames) {
            return generalNamesToMap((GeneralNames) asn1Prim);
        } else if (asn1Prim instanceof AuthorityKeyIdentifier) {
            return authorityKeyIdToMap((AuthorityKeyIdentifier) asn1Prim);
        } else if (asn1Prim instanceof BasicConstraints) {
            return basicConstraintsToMap((BasicConstraints) asn1Prim);
        } else if (asn1Prim instanceof CRLNumber) {
            CRLNumber crlNumber = (CRLNumber) asn1Prim;
            return crlNumber.getCRLNumber();
        } else if (asn1Prim instanceof SubjectKeyIdentifier) {
            SubjectKeyIdentifier ski = (SubjectKeyIdentifier) asn1Prim;
            return ski.getKeyIdentifier();
        } else if (asn1Prim instanceof ExtendedKeyUsage) {
            return extKeyUsageToList((ExtendedKeyUsage) asn1Prim);
        } else if (asn1Prim instanceof KeyPurposeId) {
            KeyPurposeId kpi = (KeyPurposeId) asn1Prim;
            return kpi.getId();
        } else if (asn1Prim instanceof KeyUsage) {
            KeyUsage ku = (KeyUsage)asn1Prim;
            return keyUsageToSet(ku);
        } else if (asn1Prim instanceof DERBitString) {
            DERBitString bitString = (DERBitString)asn1Prim;
            return bitString.getString();
        } else if (asn1Prim instanceof ASN1TaggedObject) {
            ASN1TaggedObject taggedObj = (ASN1TaggedObject)asn1Prim;
            return asn1ObjToObj(taggedObj.getObject());
        } else if (asn1Prim instanceof ASN1Sequence) {
            return asn1SeqToList((ASN1Sequence) asn1Prim);
        } else if (asn1Prim instanceof ASN1String) {
            ASN1String str = (ASN1String)asn1Prim;
            return str.getString();
        } else if (asn1Prim instanceof ASN1OctetString) {
            ASN1OctetString str = (ASN1OctetString) asn1Prim;
            return new String(str.getOctets(), "UTF-8");
        } else if (asn1Prim instanceof X500Name) {
            X500Name name = (X500Name) asn1Prim;
            return name.toString();
        } else {
            // Return the raw data if there's no clear method of decoding
            return asn1Prim.toASN1Primitive().getEncoded();
        }
    }

    private static final Map<String, Integer> keyUsageFlags =
        new HashMap<String, Integer>() {{
            put("digital_signature", KeyUsage.digitalSignature);
            put("non_repudiation", KeyUsage.nonRepudiation);
            put("key_encipherment", KeyUsage.keyEncipherment);
            put("data_encipherment", KeyUsage.dataEncipherment);
            put("key_agreement", KeyUsage.keyAgreement);
            put("key_cert_sign", KeyUsage.keyCertSign);
            put("crl_sign", KeyUsage.cRLSign);
            put("encipher_only", KeyUsage.encipherOnly);
            put("decipher_only", KeyUsage.decipherOnly);
    }};

    private static Set<String> keyUsageToSet(KeyUsage ku) {
        Set<String> ret = new HashSet<String>();
        for (String key : keyUsageFlags.keySet()) {
            if (ku.hasUsages(keyUsageFlags.get(key))) {
                ret.add(key);
            }
        }
        return ret;
    }

    private static KeyUsage setToKeyUsage(Set<String> flags) {
        int usageBitString = 0;

        for (String key: flags) {
            Integer flagBit = keyUsageFlags.get(key);

            if (flagBit == null) {
                throw new IllegalArgumentException(
                        "The provided usage key does not exist: '" + key + "'");
            }

            usageBitString |= flagBit;
        }

        return new KeyUsage(usageBitString);
    }

    private static ExtendedKeyUsage listToExtendedKeyUsage(List<String> oidList) {
        List<KeyPurposeId> usages = new ArrayList<KeyPurposeId>();

        for (String oid : oidList) {
            usages.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(oid)));
        }

        return new ExtendedKeyUsage(usages.toArray(new KeyPurposeId[usages.size()]));
    }

    private static List<Object> extKeyUsageToList(ExtendedKeyUsage eku)
            throws IOException
    {
        List<Object> ret = new ArrayList<Object>();
        for (KeyPurposeId kpid : eku.getUsages()) {
            ret.add(asn1ObjToObj(kpid));
        }
        return ret;
    }

    private static Map<String, Object> basicConstraintsToMap(BasicConstraints bc) {
        Map<String, Object> ret = new HashMap<String, Object>();
        ret.put("is_ca", bc.isCA());
        ret.put("path_len_constraint", bc.getPathLenConstraint());
        return ret;
    }

    private static BasicConstraints mapToBasicConstraints(Map<String, Object> bcMap) {
        Boolean isCa = (Boolean) bcMap.get("is_ca");
        if (isCa == null) {
            throw new IllegalArgumentException(
                    "The 'is_ca' key must be present in a basic constraint.");
        }

        BasicConstraints bc;
        Integer pathLenConstraint = (Integer) bcMap.get("path_len_constraint");
        if (pathLenConstraint != null) {
            if (!isCa) {
                throw new IllegalArgumentException(
                        "The 'path_len_constraint' key is not supported for " +
                        "an 'is_ca' value of 'false'");
            }
            bc = new BasicConstraints(pathLenConstraint);
        }
        else {
            bc = new BasicConstraints(isCa);
        }

        return bc;
    }

    private static SubjectKeyIdentifier publicKeyToSubjectKeyIdentifier(PublicKey publicKey)
            throws OperatorCreationException
    {
        SubjectPublicKeyInfo pubKeyInfo =
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        DigestCalculator digCalc =
                new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        X509ExtensionUtils utils = new X509ExtensionUtils(digCalc);
        return utils.createSubjectKeyIdentifier(pubKeyInfo);
    }

    private static AuthorityKeyIdentifier mapToAuthorityKeyIdentifier(
            Map<String, Object> authKeyIdMap) throws OperatorCreationException {
        AuthorityKeyIdentifier authorityKeyId = null;

        PublicKey pubKey = (PublicKey) authKeyIdMap.get ("public_key");
        if (pubKey != null) {
            SubjectPublicKeyInfo authPubKeyInfo =
                    SubjectPublicKeyInfo.getInstance(
                            pubKey.getEncoded());

            DigestCalculator digCalc =
                    new BcDigestCalculatorProvider().get(
                            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

            X509ExtensionUtils utils = new X509ExtensionUtils(digCalc);
            authorityKeyId = utils.createAuthorityKeyIdentifier(authPubKeyInfo);
        }

        BigInteger serialNumber = (BigInteger) authKeyIdMap.get
                ("serial_number");
        if (pubKey == null && serialNumber == null) {
            throw new IllegalArgumentException(
                    "Neither 'public_key' nor 'serial_number' provided for " +
                    "auth key identifier.  At least one of these must be " +
                    "provided.");
        }

        String issuer = (String) authKeyIdMap.get ("issuer_dn");
        if (issuer == null) {
            if (serialNumber != null) {
                throw new IllegalArgumentException(
                        "'issuer' not provided for auth key identifier " +
                        "but was expected since 'serial_number' was provided");
            }
        }
        else {
            if (serialNumber == null) {
                throw new IllegalArgumentException(
                        "'serial_number' not provided for auth key identifier" +
                        "but was expected since 'issuer' was provided");
            }

            GeneralNames issuerAsGeneralNames =
                    new GeneralNames(new GeneralName(new X500Name(issuer)));
            if (authorityKeyId != null) {
                authorityKeyId = new AuthorityKeyIdentifier(
                        authorityKeyId.getKeyIdentifier(),
                        issuerAsGeneralNames,
                        serialNumber);
            }
            else {
                authorityKeyId = new AuthorityKeyIdentifier(
                        issuerAsGeneralNames,
                        serialNumber);
            }
        }

        return authorityKeyId;
    }

    private static Map<String, Object> authorityKeyIdToMap(AuthorityKeyIdentifier akid)
            throws IOException
    {
        Map<String, Object> ret = new HashMap<String, Object>();
        ret.put("issuer", generalNamesToMap(akid.getAuthorityCertIssuer()));
        ret.put("serial_number", akid.getAuthorityCertSerialNumber());
        ret.put("key_identifier", akid.getKeyIdentifier());
        return ret;
    }

    /**
     * Convert an ASN1 Sequence to a Java list.
     *
     * @param seq The ASN1 sequence to be converted.
     * @return A List of parsed ASN1 objects contained in the provided sequence.
     * @throws IOException
     */
    private static List<Object> asn1SeqToList(ASN1Sequence seq)
            throws IOException
    {
        List<Object> ret = new ArrayList<Object>();

        for (int i=0; i < seq.size(); i++) {
            ret.add(asn1ObjToObj(seq.getObjectAt(i)));
        }

        return ret;
    }

    /** The key name each tag number represents in a GeneralNames data structure */
    private static final Map<Integer, String> generalNameTags =
            new HashMap<Integer, String>() {{
                put(0, "other_name");
                put(1, "rfc822_name");
                put(2, "dns_name");
                put(3, "x400_address");
                put(4, "directory_name");
                put(5, "edi_party_name");
                put(6, "uri");
                put(7, "ip");
                put(8, "registered_id");
            }};

    /**
     * Given type name, return the general name tag value.
     *
     * @param name The GeneralName tag name defined in generalNameTags
     * @return The tag number of the name, or null if the name doesn't exist.
     */
    private static Integer getGnTagFromName(String name) {
        for (int i=0; i < generalNameTags.size(); i++) {
            if (generalNameTags.get(i).equalsIgnoreCase(name)) {
                return i;
            }
        }

        return null;
    }

    /**
     * Convert a Bouncy Castle GeneralNames object into a Java map where the key
     * is the type of name defined, and the value is a list of names of that type.
     *
     * @param names The GeneralNames object to be parsed.
     * @return A list of the names contained in each GeneralName in the
     *         GeneralNames data structure.
     * @throws IOException
     * @see org.bouncycastle.asn1.x509.GeneralName
     */
    private static Map<String, List<String>> generalNamesToMap(GeneralNames names)
            throws IOException
    {
        if (names != null) {
            Map<String, List<String>> ret = new HashMap<String, List<String>>();
            for (GeneralName generalName : names.getNames()) {
                String type = generalNameTags.get(generalName.getTagNo());
                if (ret.get(type) == null) {
                    ret.put(type, new ArrayList<String>());
                }
                String name = (String) asn1ObjToObj(generalName.getName());
                ret.get(type).add(name);
            }

            return ret;
        } else {
            return null;
        }
    }

    /**
     * Convert a list of general name maps into a GeneralNames object.
     *
     * @param gnMap A map containing name types and a list of names.
     * @return A Bouncy Castle GeneralNames object.
     * @see #generalNamesToMap(org.bouncycastle.asn1.x509.GeneralNames)
     */
    private static GeneralNames mapToGeneralNames(Map<String, List<String>> gnMap) {
        List<GeneralName> ret = new ArrayList<GeneralName>();
        for (String type: gnMap.keySet()) {
            Integer tag = getGnTagFromName(type);

            if (tag == null) {
                throw new IllegalArgumentException(
                               "Could not find a tag number for the type name '" +
                                type + '"');
            }

            for (String name: gnMap.get(type)) {
                ret.add(new GeneralName(tag, name));
            }

        }
        return new GeneralNames(ret.toArray(new GeneralName[ret.size()]));
    }
}
