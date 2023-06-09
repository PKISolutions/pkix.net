using System;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Contains enumeration values for certificate state used by <see cref="ICertPropReaderD"/> interface.
    /// </summary>
    public enum AdcsPropCertState {
        /// <summary>
        /// The signing certificate is incomplete.
        /// </summary>
        Incomplete    = 0,
        /// <summary>
        /// The signing certificate is unavailable.
        /// </summary>
        Unavailable   = 1,
        /// <summary>
        /// The signing certificate has been revoked.
        /// </summary>
        Revoked       = 2,
        /// <summary>
        /// The signing certificate is valid.
        /// </summary>
        Valid         = 3,
        /// <summary>
        /// The signing certificate has expired.
        /// </summary>
        Expired       = 4,
        /// <summary>
        /// The property is unavailable.
        /// </summary>
        NotApplicable = unchecked((Int32)0xffffffff)
    }
}