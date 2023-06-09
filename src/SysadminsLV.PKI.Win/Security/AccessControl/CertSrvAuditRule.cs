using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Represents certification authority audit rule object.
    /// </summary>
    public sealed class CertSrvAuditRule : AuditRule<CertSrvRights> {
        /// <inheritdoc />
        public CertSrvAuditRule(
            IdentityReference identity,
            CertSrvRights accessMask,
            AuditFlags flags)
            : base(identity, accessMask, InheritanceFlags.None, PropagationFlags.None, flags) { }
    }
}
