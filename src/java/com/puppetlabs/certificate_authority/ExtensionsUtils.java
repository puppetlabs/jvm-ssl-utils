package com.puppetlabs.certificate_authority;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utilities for working with X509 extensions.
 */
public class ExtensionsUtils {
    /**
     * Given a Java X509Certificate object, return a list of maps representing
     * all the X509 extensions embedded in the certificate. If no extensions
     * exist on the certificate, the null is returned.
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
        for (Attribute attr : csr.getAttributes()) {
            if (attr.getAttrType() == PKCSObjectIdentifiers.pkcs_9_at_extensionRequest) {
                // TODO: All this casting shouldn't be needed.
                ASN1Set extsAsn1 = attr.getAttrValues();
                if (extsAsn1 != null) {
                    DERSet derSet = (DERSet) extsAsn1.getObjectAt(0);
                    if (derSet != null) {
                        return (Extensions) derSet.getObjectAt(0);
                    } else {
                        return null;
                    }
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
            throws IOException
    {
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
    static Extension parseExtensionObject(Map<String, Object> extMap)
            throws IOException
    {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier((String)extMap.get("oid"));

        ASN1Object ret;
        if (oid.equals(Extension.subjectAlternativeName) ||
            oid.equals(Extension.issuerAlternativeName))
        {
            ret = mapToGeneralNames((Map<String, List<String>>) extMap.get("value"));
        } else {
            throw new IllegalArgumentException(
                    "Parsing an extension with an OID=" +
                    oid.getId() + " is not yet supported.");
        }

        return new Extension(oid, (Boolean)extMap.get("critical"), new DEROctetString(ret));
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
            DERBitString bs = new DERBitString(data);
            return new KeyUsage(bs.getPadBits());
        } else if (oid.equals(Extension.extendedKeyUsage)) {
            return ExtendedKeyUsage.getInstance(data);
        } else if (oid.equals(MiscObjectIdentifiers.netscapeCertComment)) {
            return new DERPrintableString(new String(data, "UTF8"));
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
            return keyUsageToMap(ku);
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
            ASN1OctetString str = (ASN1OctetString)asn1Prim;
            return new String(str.getOctets(), "UTF-8");
        } else {
            // Return the raw data if there's no clear method of decoding
            return asn1Prim.toASN1Primitive().getEncoded();
        }
    }

    private static Map<String, Boolean> keyUsageToMap(KeyUsage ku) {
        HashMap<String, Boolean> ret = new HashMap<String, Boolean>();
        ret.put("digital_signature", ku.hasUsages(KeyUsage.digitalSignature));
        ret.put("non_repudiation",   ku.hasUsages(KeyUsage.nonRepudiation));
        ret.put("key_encipherment",  ku.hasUsages(KeyUsage.keyEncipherment));
        ret.put("data_encipherment", ku.hasUsages(KeyUsage.dataEncipherment));
        ret.put("key_agreement",     ku.hasUsages(KeyUsage.keyAgreement));
        ret.put("key_cert_sign",     ku.hasUsages(KeyUsage.keyCertSign));
        ret.put("crl_sign",          ku.hasUsages(KeyUsage.cRLSign));
        ret.put("encipher_only",     ku.hasUsages(KeyUsage.encipherOnly));
        ret.put("decipher_only",     ku.hasUsages(KeyUsage.decipherOnly));
        return ret;
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

                String name = (String) asn1ObjToObj(generalName.getName().toASN1Primitive());
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
