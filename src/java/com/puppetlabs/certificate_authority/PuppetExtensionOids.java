package com.puppetlabs.certificate_authority;

/**
 * Definitions for Puppet Labs extension OIDs.
 */
public interface PuppetExtensionOids {
    static final String parent           = "1.3.6.1.4.1.34380";
    static final String certExt          = "1.3.6.1.4.1.34380.1";
    static final String regCertExt       = "1.3.6.1.4.1.34380.1.1";
    static final String nodeUid          = "1.3.6.1.4.1.34380.1.1.1";
    static final String nodeInstanceId   = "1.3.6.1.4.1.34380.1.1.2";
    static final String nodeImageName    = "1.3.6.1.4.1.34380.1.1.3";
    static final String nodePresharedKey = "1.3.6.1.4.1.34380.1.1.4";
    static final String privateCertExt   = "1.3.6.1.4.1.34380.1.2";
}
