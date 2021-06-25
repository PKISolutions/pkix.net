using System;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a generic Certification Authority configuration entry.
    /// </summary>
    public class CertSrvConfigEntry {
        /// <summary>
        /// Gets or sets the configuration node name. Can be empty string for root node.
        /// </summary>
        public String NodeName { get; set; }
        /// <summary>
        /// Gets or sets configuration entry name.
        /// </summary>
        public String EntryName { get; set; }
        /// <summary>
        /// Gets or sets the value associated with configuration entry.
        /// </summary>
        public Object Value { get; set; }
    }
}