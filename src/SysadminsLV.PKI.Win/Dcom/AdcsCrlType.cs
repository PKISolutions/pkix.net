using System;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Contains enumeration of CRL types to publish by Certification Authority (CA). This enumeration is used by <see cref="ICertCrlAdminD"/> interface.
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
    /// </summary>
    [Flags]
    enum AdcsCrlPublishType {
        /// <summary>
        /// A base CRL is published, or the most recent base CRL is republished if <strong>RePublish</strong> is set.
        /// </summary>
        BaseCRL   = 1,
        /// <summary>
        /// A delta CRL is published, or the most recent delta CRL is republished if <strong>RePublish</strong> is set.
        /// Note that if the CA has not enabled delta CRL publishing, use of this flag will result in an error.
        /// </summary>
        DeltaCRL  = 2,
        /// <summary>
        /// The most recent base or delta CRL, as specified by <strong>BaseCRL</strong> or <strong>DeltaCRL</strong>, is republished.
        /// The CA will not republish a CRL to a CRL distribution point if the CRL at the distribution point is already the most recent CRL.
        /// </summary>
        RePublish = 0x10
    }
}