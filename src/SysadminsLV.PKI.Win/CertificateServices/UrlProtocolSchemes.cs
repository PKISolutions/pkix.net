namespace PKI.CertificateServices {
    /// <summary>
    /// This enumeration contains supported by Active Directory Certificate Services (<strong>ADCS</strong>)
    /// URL type for <i>authority information access</i> (<strong>AIA</strong>) and <i>CRL distribution points</i>
    /// (<strong>CDP</strong>) extensions.
    /// </summary>
    public enum UrlProtocolSchemes {
        /// <summary>
        /// Url protocol cannot be determined.
        /// </summary>
        Unknown,
        /// <summary>
        /// Identifies the local file system path.
        /// </summary>
        Local,
        /// <summary>
        /// Identifies the Universal Naming Convention path (network share).
        /// </summary>
        UNC,
        /// <summary>
        /// Identifies the Hyper-Text Transfer Protocol.
        /// </summary>
        HTTP,
        /// <summary>
        /// Identifies the Lightweight Directory Access Protocol.
        /// </summary>
        LDAP
    }
}
