using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Represents an abstraction of an access control entry (ACE) that defines an access rule for a Certification
    /// Authority. This class cannot be inherited.
    /// </summary>
    public sealed class CertSrvAccessRule : AccessRule<CertSrvRights> {

        /// <param name="identity">
        ///		An IdentityReference object that encapsulates a reference to a user account.
        /// </param>
        /// <param name="accessMask">
        ///		One of the <see cref="CertSrvRights"/> values that specifies the type of operation
        ///		associated with the access rule.
        /// </param>
        /// <param name="type">
        ///		One of the <see cref="AccessControlType"/> values that specifies whether to allow or deny the operation.
        /// </param>
    public CertSrvAccessRule(
            IdentityReference identity,
            CertSrvRights accessMask,
            AccessControlType type)
            : base(identity, accessMask, InheritanceFlags.None, PropagationFlags.None, type) { }
    }
}
