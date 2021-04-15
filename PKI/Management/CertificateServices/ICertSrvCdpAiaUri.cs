using System;

namespace PKI.Management.CertificateServices {
    /// <summary>
    /// Represents an abstraction over CRL Distribution Point or Authority Information Access configuration URL.
    /// </summary>
    public interface ICertSrvCdpAiaUri {
        /// <summary>
        /// Gets the registry-based URI in the format: &lt;PublishFlags&gt;:&lt;URI&gt;.
        /// </summary>
        /// <returns>Registry-based URI.</returns>
        String GetRegUri();
    }
}