using System;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Contains enumeration of Key Recovery Agent (KRA) certificate statuses.
    /// </summary>
    public enum AdcsPropKraCertStatus {
        /// <summary>
        /// Certificate is expired.
        /// </summary>
        Expired       = 0,
        /// <summary>
        /// Certificate cannot be found.
        /// </summary>
        NotFound      = 1,
        /// <summary>
        /// Certificate is revoked.
        /// </summary>
        Revoked       = 2,
        /// <summary>
        /// Certificate is valid for key encryption.
        /// </summary>
        Valid         = 3,
        /// <summary>
        /// Certificate is not valid for key encryption.
        /// </summary>
        Invalid       = 4,
        /// <summary>
        /// Certificate is not trusted by Certification Authority.
        /// </summary>
        Untrusted     = 5,
        /// <summary>
        /// Certificate is assigned, but not loaded to Certification Authority runtime. Certification Authority service restart is required.
        /// </summary>
        NotLoaded     = 6,
        /// <summary>
        /// The property is unavailable.
        /// </summary>
        NotApplicable = unchecked((Int32)0xffffffff)
    }
}