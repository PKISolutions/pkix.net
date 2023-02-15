namespace SysadminsLV.PKI.Tools.MessageOperations {
    /// <summary>
    /// Represents supported digital signature schemes.
    /// </summary>
    public enum SignaturePadding {
        /// <summary>
        /// No padding is used.
        /// </summary>
        None = 0,
        /// <summary>
        /// The PKCS1 padding scheme is used to create or verify signature.
        /// </summary>
        PKCS1 = 2,
        /// <summary>
        /// The Probabilistic Signature Scheme (PSS) padding scheme padding scheme is used to create or
        /// verify signature
        /// </summary>
        PSS = 8
    }
}