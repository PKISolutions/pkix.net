using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Represents certificate template audit access rule object.
    /// </summary>
    public sealed class CertTemplateAuditRule : AuditRule<CertTemplateRights> {
        /// <inheritdoc />
        public CertTemplateAuditRule(
            IdentityReference identity,
            CertTemplateRights accessMask,
            AuditFlags flags)
            : base(identity, accessMask, InheritanceFlags.None, PropagationFlags.None, flags) { }
    }
}