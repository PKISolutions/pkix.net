using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using PKI.CertificateTemplates;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Security.AccessControl;

/// <summary>
/// Represents managed ADCS certificate template security descriptor (ACL). This object is a wrapper around <see cref="ActiveDirectorySecurity"/>.
/// </summary>
public sealed class CertTemplateSecurityDescriptor : CommonObjectSecurity {
    const String GUID_ENROLL     = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
    const String GUID_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";
    //readonly String _x500Name;
    readonly String _x500Path;
    readonly Int32 _schemaVersion;

    internal CertTemplateSecurityDescriptor(CertificateTemplate template) : base(false) {
        DisplayName = template.DisplayName;
        _schemaVersion = template.SchemaVersion;
        _x500Path = "LDAP://" + template.DistinguishedName;
        fromActiveDirectorySecurity();
    }

    /// <summary>
    /// Gets the display name of the certificate template.
    /// </summary>
    public String DisplayName { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertTemplateAccessRule"/> class that represents a new access
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
    ///        A new <see cref="CertTemplateAccessRule"/> object that represents a new access control rule
    ///        for the specified user, with the specified access rights, access control, and flags.
    /// </returns>
    public override AccessRule AccessRuleFactory(IdentityReference identityReference, Int32 accessMask, Boolean isInherited,
        InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type) {
        return new CertTemplateAccessRule(identityReference, (CertTemplateRights)accessMask, type);
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
    /// 
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
    public Boolean AddAccessRule(CertTemplateAccessRule rule) {
        AuthorizationRuleCollection rules = GetAccessRules(true, false, typeof(NTAccount));
        CertTemplateRights effectiveRuleRights = rule.Rights;
        if (_schemaVersion == 1 && (rule.Rights & CertTemplateRights.Autoenroll) > 0) {
            effectiveRuleRights &= ~CertTemplateRights.Autoenroll;
        }

        CertTemplateAccessRule existingRule = rules
            .Cast<CertTemplateAccessRule>()
            .FirstOrDefault(x => x.IdentityReference.Value.Equals(rule.IdentityReference.Value, StringComparison.OrdinalIgnoreCase) && x.AccessControlType == rule.AccessControlType);
        if (existingRule != null) {
            RemoveAccessRule(existingRule);
            var ace = new CertTemplateAccessRule(
                rule.IdentityReference,
                effectiveRuleRights | existingRule.Rights,
                rule.AccessControlType);
            base.AddAccessRule(ace);
            return true;
        }
        base.AddAccessRule(rule);
        return true;
    }

    /// <inheritdoc />
    /// <returns>This method always returns <strong>False</strong>.</returns>
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
        AccessRule existingRule = rules
            .Cast<CertTemplateAccessRule>()
            .FirstOrDefault(x => x.IdentityReference.Value.Equals(identity.Value, StringComparison.OrdinalIgnoreCase) && x.AccessControlType == accessType);
        return existingRule != null && RemoveAccessRule(existingRule);
    }
    /// <summary>
    /// This member is not implemented.
    /// </summary>
    /// <param name="identity">
    ///        An <see cref="IdentityReference"/> object that represents a user account.
    /// </param>
    public override void PurgeAuditRules(IdentityReference identity) { }
    /// <inheritdoc />
    public override Type AccessRightType => typeof(CertTemplateRights);
    /// <inheritdoc />
    public override Type AccessRuleType => typeof(CertTemplateAccessRule);
    /// <inheritdoc />
    public override Type AuditRuleType => typeof(CertTemplateAuditRule);

    ActiveDirectorySecurity toAdSecurity(DirectoryEntry entry) {
        ActiveDirectorySecurity dsSecurity = entry.ObjectSecurity;
        // clear all existing ACEs
        dsSecurity
            .GetAccessRules(true, true, typeof(NTAccount))
            .Cast<ActiveDirectoryAccessRule>()
            .Select(x => x.IdentityReference)
            .Distinct()
            .ToList()
            .ForEach(x => dsSecurity.PurgeAccessRules(x));
        // iterate over local ACEs and translate to DS ACL
        foreach (CertTemplateAccessRule localAce in GetAccessRules(true, false, typeof(NTAccount))) {
            CertTemplateRights localRights = localAce.Rights;
            if ((localRights & CertTemplateRights.FullControl) > 0) {
                var ace = new ActiveDirectoryAccessRule(
                    localAce.IdentityReference,
                    ActiveDirectoryRights.GenericAll,
                    localAce.AccessControlType);
                dsSecurity.AddAccessRule(ace);
                continue;
            }
            CertTemplateRights rw = localRights & (CertTemplateRights.Read | CertTemplateRights.Write);
            if (rw > 0) {
                ActiveDirectoryRights tempRights;
                if (rw == (CertTemplateRights.Read | CertTemplateRights.Write)) {
                    tempRights = ActiveDirectoryRights.CreateChild
                                 | ActiveDirectoryRights.DeleteChild
                                 | ActiveDirectoryRights.Self
                                 | ActiveDirectoryRights.WriteProperty
                                 | ActiveDirectoryRights.DeleteTree
                                 | ActiveDirectoryRights.Delete
                                 | ActiveDirectoryRights.GenericRead
                                 | ActiveDirectoryRights.WriteDacl
                                 | ActiveDirectoryRights.WriteOwner;
                } else if (rw == CertTemplateRights.Read) {
                    tempRights = ActiveDirectoryRights.GenericRead;
                } else {
                    tempRights = ActiveDirectoryRights.Self
                                 | ActiveDirectoryRights.WriteProperty
                                 | ActiveDirectoryRights.WriteDacl
                                 | ActiveDirectoryRights.WriteOwner;
                }
                var ace = new ActiveDirectoryAccessRule(
                    localAce.IdentityReference,
                    tempRights,
                    localAce.AccessControlType);
                dsSecurity.AddAccessRule(ace);
            }
            if ((localRights & CertTemplateRights.Enroll) > 0) {
                var ace = new ActiveDirectoryAccessRule(
                    localAce.IdentityReference,
                    ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.WriteProperty | ActiveDirectoryRights.ExtendedRight,
                    localAce.AccessControlType,
                    new Guid(GUID_ENROLL));
                dsSecurity.AddAccessRule(ace);
            }
            if ((localRights & CertTemplateRights.Autoenroll) > 0) {
                var ace = new ActiveDirectoryAccessRule(
                    localAce.IdentityReference,
                    ActiveDirectoryRights.ExtendedRight,
                    localAce.AccessControlType,
                    new Guid(GUID_AUTOENROLL));
                dsSecurity.AddAccessRule(ace);
            }
        }
        return dsSecurity;
    }

    /// <summary>
    /// Translates this object to Active Directory compatible security descriptor.
    /// </summary>
    /// <returns></returns>
    public ActiveDirectorySecurity ToActiveDirectorySecurity() {
        using var entry = new DirectoryEntry(_x500Path);
        return toAdSecurity(entry);
    }
    /// <summary>
    /// Writes this object to a securable object's Access Control List.
    /// </summary>
    public void SetObjectSecurity() {
        using var entry = new DirectoryEntry(_x500Path);
        toAdSecurity(entry);
        entry.CommitChanges();
    }

    void fromActiveDirectorySecurity() {
        ActiveDirectorySecurity dsSecurity;
        using (var entry = new DirectoryEntry(_x500Path)) {
            dsSecurity = entry.ObjectSecurity;
        }

        try {
            SetOwner(dsSecurity.GetOwner(typeof(NTAccount)));
        } catch {
            SetOwner(dsSecurity.GetOwner(typeof(SecurityIdentifier)));
        }

        IEnumerable<IdentityReference> users = dsSecurity
            .GetAccessRules(true, true, typeof(NTAccount))
            .Cast<ActiveDirectoryAccessRule>()
            .Select(x => x.IdentityReference)
            .Distinct();

        foreach (IdentityReference user in users) {
            foreach (AccessControlType accessType in Enum.GetValues(typeof(AccessControlType))) {
                CertTemplateRights rights = 0;
                IEnumerable<ActiveDirectoryAccessRule> aceList = dsSecurity.GetAccessRules(true, true, typeof(NTAccount))
                    .Cast<ActiveDirectoryAccessRule>()
                    .Where(x => x.IdentityReference == user && x.AccessControlType == accessType);
                foreach (ActiveDirectoryAccessRule ace in aceList) {
                    ActiveDirectoryRights aceRights = ace.ActiveDirectoryRights;
                    if (aceRights.HasFlag(ActiveDirectoryRights.GenericRead) || aceRights.HasFlag(ActiveDirectoryRights.GenericExecute)) {
                        rights |= CertTemplateRights.Read;
                    }
                    if (aceRights.HasFlag(ActiveDirectoryRights.WriteDacl)) {
                        rights |= CertTemplateRights.Write;
                    }
                    if (aceRights.HasFlag(ActiveDirectoryRights.GenericAll)) {
                        rights |= CertTemplateRights.FullControl;
                    }
                    if (aceRights.HasFlag(ActiveDirectoryRights.ExtendedRight)) {
                        switch (ace.ObjectType.ToString()) {
                            case GUID_ENROLL:
                                rights |= CertTemplateRights.Enroll;
                                break;
                            case GUID_AUTOENROLL:
                                rights |= CertTemplateRights.Autoenroll;
                                break;
                        }
                    }
                }
                if (rights > 0) {
                    AddAccessRule(new CertTemplateAccessRule(user, rights, accessType));
                }
            }
        }
    }
}