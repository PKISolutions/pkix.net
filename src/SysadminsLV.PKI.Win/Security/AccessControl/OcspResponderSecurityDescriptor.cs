using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using CERTADMINLib;
using SysadminsLV.PKI.Dcom.Implementations;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Management.CertificateServices;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Security.AccessControl;
/// <summary>
/// Represents the access control for a Microsoft OCSP Online Responder.
/// </summary>
/// <remarks>This class has no public constructors.</remarks>
public sealed class OcspResponderSecurityDescriptor : CommonObjectSecurity {

    internal OcspResponderSecurityDescriptor(OcspResponder onlineResponder) : base(false) {
        ComputerName = onlineResponder.ComputerName;
    }
    /// <summary>
    /// Gets the host fully qualified domain name (FQDN) of the server where online responder is installed.
    /// </summary>
    public String ComputerName { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="OcspResponderAccessRule"/> class that represents a new access
    /// control rule for the specified user, with the specified access rights, access control, and flags.
    /// </summary>
    /// <param name="identityReference">
    ///        An <see cref="IdentityReference"/> object that represents a user account.
    /// </param>
    /// <param name="accessMask">
    ///        An integer that specifies an access type.
    /// </param>
    /// <param name="isInherited">
    ///        <strong>True</strong> if the access rule is inherited; otherwise, <strong>False</strong>. This parameter
    ///        is not used and is always set to <strong>False</strong>.
    /// </param>
    /// <param name="inheritanceFlags">
    ///        One of the <see cref="InheritanceFlags"/> values that specifies how to propagate access masks to child
    ///        objects. This parameter is not used and is always set to <strong>None</strong>.
    /// </param>
    /// <param name="propagationFlags">
    ///        One of the <see cref="PropagationFlags"/> values that specifies how to propagate Access Control Entries
    ///        (ACEs) to child objects. This parameter is not used and is always set to <strong>None</strong>.
    /// </param>
    /// <param name="type">
    ///        One of the <see cref="AccessControlType"/> values that specifies whether access is allowed or denied.
    /// </param>
    /// <returns>
    ///        A new <see cref="OcspResponderAccessRule"/> object that represents a new access control rule
    ///        for the specified user, with the specified access rights, access control, and flags.
    /// </returns>
    public override AccessRule AccessRuleFactory(IdentityReference identityReference, Int32 accessMask, Boolean isInherited,
        InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type) {
        return new OcspResponderAccessRule(identityReference, (OcspResponderRights)accessMask, type);
    }
    ///  <summary>
    ///  This member is not implemented.
    ///  </summary>
    ///  <param name="identityReference">
    ///         An <see cref="IdentityReference"/> object that represents a user account.
    ///  </param>
    ///  <param name="accessMask">
    ///         An integer that specifies an access type.
    ///  </param>
    ///  <param name="isInherited">
    ///         <strong>True</strong> if the access rule is inherited; otherwise, <strong>False</strong>. This parameter
    ///         is not used and is always set to <strong>False</strong>.
    ///  </param>
    ///  <param name="inheritanceFlags">
    ///         One of the <see cref="InheritanceFlags"/> values that specifies how to propagate access masks to child
    ///         objects. This parameter is not used and is always set to <strong>None</strong>.
    ///  </param>
    ///  <param name="propagationFlags">
    ///         One of the <see cref="PropagationFlags"/> values that specifies how to propagate Access Control Entries
    ///         (ACEs) to child objects. This parameter is not used and is always set to <strong>None</strong>.
    ///  </param>
    ///  <param name="flags">
    ///         One of the <see cref="AuditFlags"/> values that specifies the type of auditing to perform.
    ///  </param>
    /// <exception cref="NotSupportedException">The exception is thrown when the method is invoked.</exception>
    /// <returns>This method always throws exception.</returns>
    /// <remarks>This member is not implemented.</remarks>
    public override AuditRule AuditRuleFactory(IdentityReference identityReference, Int32 accessMask, Boolean isInherited,
        InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags) {
        throw new NotSupportedException(ErrorHelper.E_AUDITNOTSUPPOERTED);
    }
    /// <summary>
    ///        Adds the specified access rule to the Discretionary Access Control List (DACL) associated with this
    ///        <see cref="CommonObjectSecurity"/> object.
    /// </summary>
    /// <param name="rule">The access rule to add.</param>
    /// <returns><strong>True</strong> if the access rule was added, otherwise <strong>False</strong>.</returns>
    /// <remarks>
    ///        The method does nothing if current DACL already contains identity specified in the <strong>rule</strong>
    ///        parameter. DACL merging is not supported.
    /// </remarks>
    public Boolean AddAccessRule(OcspResponderAccessRule rule) {
        AuthorizationRuleCollection rules = GetAccessRules(true, false, typeof(NTAccount));
        OcspResponderAccessRule existingRule = rules
            .Cast<OcspResponderAccessRule>()
            .FirstOrDefault(x => x.IdentityReference.Value.Equals(rule.IdentityReference.Value, StringComparison.OrdinalIgnoreCase) && x.AccessControlType == rule.AccessControlType);
        if (existingRule != null) {
            RemoveAccessRule(existingRule);
            var ace = new OcspResponderAccessRule(
                rule.IdentityReference,
                rule.Rights | existingRule.Rights,
                rule.AccessControlType);
            base.AddAccessRule(ace);
            return true;
        }
        base.AddAccessRule(rule);
        return true;
    }
    ///  <summary>
    ///  This member is not implemented.
    ///  </summary>
    ///  <param name="modification">
    ///         The modification to apply to the SACL.
    ///  </param>
    ///  <param name="rule">
    ///         The audit rule to modify.
    ///  </param>
    ///  <param name="modified">
    ///         <strong>True</strong> if the SACL is successfully modified; otherwise, <strong>False</strong>.
    ///  </param>
    /// <exception cref="NotSupportedException">The exception is thrown when the method is invoked.</exception>
    /// <returns>This method always throws exception.</returns>
    /// <remarks>This member is not implemented.</remarks>
    public override Boolean ModifyAuditRule(AccessControlModification modification, AuditRule rule, out Boolean modified) {
        modified = false;
        return modified;
    }
    /// <summary>
    /// Removes access rules that contain the same security identifier and access type as the specified access rule from the
    /// Discretionary Access Control List (DACL).
    /// </summary>
    /// <param name="identity">The identity to which the access rule applies.</param>
    /// <param name="accessType">The valid access control type.</param>
    /// <returns><strong>True</strong> if matching ACE was found and removed, otherwise <strong>False</strong>.</returns>
    public Boolean RemoveAccessRule(IdentityReference identity, AccessControlType accessType) {
        AuthorizationRuleCollection rules = GetAccessRules(true, false, typeof(NTAccount));
        OcspResponderAccessRule existingRule = rules
            .Cast<OcspResponderAccessRule>()
            .FirstOrDefault(x => x.IdentityReference.Value.Equals(identity.Value, StringComparison.OrdinalIgnoreCase) && x.AccessControlType == accessType);
        return existingRule != null && RemoveAccessRule(existingRule);
    }
    /// <summary>
    /// This member is not implemented.
    /// </summary>
    /// <param name="identity">
    ///        An <see cref="IdentityReference"/> object that represents a user account.
    /// </param>
    /// <exception cref="NotSupportedException">The exception is thrown when the method is invoked.</exception>
    public override void PurgeAuditRules(IdentityReference identity) { }
    /// <inheritdoc />
    public override Type AccessRightType => typeof(OcspResponderRights);
    /// <inheritdoc />
    public override Type AccessRuleType => typeof(OcspResponderAccessRule);
    /// <inheritdoc />
    public override Type AuditRuleType => typeof(OcspResponderAuditRule);
    ///  <summary>
    ///  Writes this object to a securable object's Access Control List.
    ///  </summary>
    ///  <exception cref="ServerUnavailableException">
    ///         The target Online Responder server could not be contacted via remote registry and RPC protocol.
    ///  </exception>
    public void SetObjectSecurity() {
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            ocspAdmin.SetSecurity(ComputerName, GetSecurityDescriptorSddlForm(AccessControlSections.All));
        } catch (COMException cex) {
            if (cex.ErrorCode == ErrorHelper.RpcUnavailableException) {
                var e = new ServerUnavailableException(ComputerName);
                e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
                throw e;
            }
        } finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }
}
