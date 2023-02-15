using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a collection of Online Responder Array members.
    /// </summary>
    public class OcspResponderMemberInfoCollection : BasicCollection<OcspResponderMemberInfo> {
        /// <inheritdoc />
        public OcspResponderMemberInfoCollection() { }
        /// <inheritdoc />
        public OcspResponderMemberInfoCollection(IEnumerable<OcspResponderMemberInfo> collection) : base(collection) { }
    }
}
