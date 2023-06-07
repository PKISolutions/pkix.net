using System;
using System.Linq;
using Microsoft.Win32;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Management.CertificateServices;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateServices.PolicyModule;
/// <summary>
/// Represents Certification Authority's policy module processing settings.
/// </summary>
public class EditFlag {
    CertSrvPlatformVersion version;
    String configString, activePolicyModule;
    Boolean isEnterprise;

    /// <param name="certificateAuthority">Specifies an existing <see cref="CertificateAuthority"/> object.</param>
    /// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
    public EditFlag(CertificateAuthority certificateAuthority) {
        if (!String.IsNullOrEmpty(certificateAuthority.Name)) {
            m_initialize(certificateAuthority);
        } else { throw new UninitializedObjectException(); }
    }

    /// <summary>
    /// Gets the common name of the Certification Authority in a sanitized form as specified in
    /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
    /// </summary>
    public String Name { get; private set; }
    /// <summary>
    /// Gets the display name of the Certification Authority (sanitized characters are decoded to textual characters).
    /// </summary>
    public String DisplayName { get; private set; }
    /// <summary>
    /// Gets the host fully qualified domain name (FQDN) of the server where Certification Authority is installed.
    /// </summary>
    public String ComputerName { get; private set; }
    /// <summary>
    /// Gets enabled policy module flags. Possible flags are listed in <see cref="PolicyModuleFlagEnum"/>.
    /// </summary>
    public PolicyModuleFlagEnum EditFlags { get; private set; }
    /// <summary>
    /// Indicates whether the object was modified after it was instantiated.
    /// </summary>
    public Boolean IsModified { get; private set; }

    void m_initialize(CertificateAuthority certificateAuthority) {
        Name = certificateAuthority.Name;
        DisplayName = certificateAuthority.DisplayName;
        ComputerName = certificateAuthority.ComputerName;
        configString = certificateAuthority.ConfigString;
        version = certificateAuthority.Version;
        isEnterprise = certificateAuthority.IsEnterprise;
        if (CryptoRegistry.Ping(ComputerName)) {
            activePolicyModule = (String)CryptoRegistry.GetRReg("Active", $@"{Name}\PolicyModules", ComputerName);
            EditFlags = (PolicyModuleFlagEnum)CryptoRegistry.GetRReg("EditFlags", $@"{Name}\PolicyModules\{activePolicyModule}", ComputerName);
        } else {
            if (CertificateAuthority.Ping(ComputerName)) {
                activePolicyModule = (String)CryptoRegistry.GetRegFallback(configString, "PolicyModules", "EditFlags");
                EditFlags = (PolicyModuleFlagEnum)CryptoRegistry.GetRegFallback(configString, $@"PolicyModules\{activePolicyModule}", "EditFlags");
            } else {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), (OfflineSource)3);
                throw e;
            }
        }
    }

    /// <summary>
    /// Adds policy module flags to enable on a specified Certification Authority. Multiple
    /// flags can be added at the time.
    /// </summary>
    /// <param name="flags">One or more flags defined in <see cref="PolicyModuleFlagEnum"/> enumeration.</param>
    /// <exception cref="UninitializedObjectException">If the object is not initialized through one of the class constructors.</exception>
    /// <exception cref="ArgumentException">The data in the <strong>flags</strong> parameter
    /// contains policy module flags that are not supported by a current Certification Authority version.</exception>
    public void Add(PolicyModuleFlagEnum flags) {
        Int32[] existing = EnumFlags.GetEnabled(typeof(PolicyModuleFlagEnum), (Int32)EditFlags);
        Int32[] newf = EnumFlags.GetEnabled(typeof(PolicyModuleFlagEnum), (Int32)flags);
        if (version == CertSrvPlatformVersion.Win2003 &&
            ((Int32)flags & (Int32)PolicyModuleFlagEnum.EnableOCSPRevNoCheck) != 0 ||
            ((Int32)flags & (Int32)PolicyModuleFlagEnum.EnableRenewOnBehalfOf) != 0
        ) {
            throw new ArgumentException("This certification authority version do not support specified flag or flags.");
        }
        if (version == CertSrvPlatformVersion.Win2008 && ((Int32)flags & (Int32)PolicyModuleFlagEnum.EnableRenewOnBehalfOf) != 0) {
            throw new ArgumentException();
        }
        foreach (Int32 item in newf.Where(item => !EnumFlags.Contains(existing, item))) {
            EditFlags = (PolicyModuleFlagEnum)((Int32)EditFlags + item);
            IsModified = true;
        }
    }
    /// <summary>
    /// Removes policy module flags from a specified Certification Authority. Multiple
    /// flags can be removed at the time.
    /// </summary>
    /// <param name="flags">One or more flags defined in <see cref="PolicyModuleFlagEnum"/> enumeration.</param>
    public void Remove(PolicyModuleFlagEnum flags) {
        Int32[] existing = EnumFlags.GetEnabled(typeof(PolicyModuleFlagEnum), (Int32)EditFlags);
        Int32[] newf = EnumFlags.GetEnabled(typeof(PolicyModuleFlagEnum), (Int32)flags);
        foreach (Int32 item in newf.Where(item => EnumFlags.Contains(existing, item))) {
            EditFlags = (PolicyModuleFlagEnum)((Int32)EditFlags - item);
            IsModified = true;
        }
    }
    /// <summary>
    /// Restores default policy module flags on a specified Certification Authority. The method do not
    /// writes default flags to a configuration. After calling this method call <see cref="SetInfo"/> method to write
    /// the values to a configuration.
    /// </summary>
    ///<remarks>The following default flags are defined depending on a CA type:
    /// <list type="table">
    /// <listheader>
    ///        <term>CA type</term>
    ///        <description>Default flags</description>
    /// </listheader>
    /// <item>
    ///        <term>Standalone CA</term>
    ///        <description>
    ///            <list type="bullet">
    ///                <item><strong>RequestExtensionList</strong></item>
    ///                <item><strong>DisableExtensionList</strong></item>
    ///                <item><strong>AddOldKeyUsage</strong></item>
    ///                <item><strong>AttributeEndDate</strong></item>
    ///                <item><strong>BasicConstraintsCritical</strong></item>
    ///                <item><strong>BasicConstraintsCA</strong></item>
    ///                <item><strong>EnableAKIKeyID</strong></item>
    ///                <item><strong>AttributeCA</strong></item>
    ///                <item><strong>AttributeEKU</strong></item>
    ///            </list>
    ///        </description>
    /// </item>
    /// <item>
    ///        <term>Enterprise CA</term>
    ///        <description>
    ///            <list type="bullet">
    ///                <item><strong>RequestExtensionList</strong></item>
    ///             <item><strong>DisableExtensionList</strong></item>
    ///             <item><strong>AddOldKeyUsage</strong></item>
    ///             <item><strong>BasicConstraintsCritical</strong></item>
    ///             <item><strong>EnableAKIKeyID</strong></item>
    ///             <item><strong>EnableDefaultSMIME</strong></item>
    ///             <item><strong>EnableChaseClientDC</strong></item>
    ///         </list>
    ///     </description>
    /// </item>
    /// </list>
    /// </remarks>
    public void Restore() {
        if (isEnterprise) {
            EditFlags = PolicyModuleFlagEnum.RequestExtensionList |
                        PolicyModuleFlagEnum.DisableExtensionList |
                        PolicyModuleFlagEnum.AddOldKeyUsage |
                        PolicyModuleFlagEnum.AttributeEndDate |
                        PolicyModuleFlagEnum.BasicConstraintsCritical |
                        PolicyModuleFlagEnum.BasicConstraintsCA |
                        PolicyModuleFlagEnum.EnableAKIKeyID |
                        PolicyModuleFlagEnum.AttributeCA |
                        PolicyModuleFlagEnum.AttributeEKU;

        } else {
            EditFlags = PolicyModuleFlagEnum.RequestExtensionList |
                        PolicyModuleFlagEnum.DisableExtensionList |
                        PolicyModuleFlagEnum.AddOldKeyUsage |
                        PolicyModuleFlagEnum.BasicConstraintsCritical |
                        PolicyModuleFlagEnum.EnableAKIKeyID |
                        PolicyModuleFlagEnum.EnableDefaultSMIME |
                        PolicyModuleFlagEnum.EnableChaseClientDC;
        }
        IsModified = true;
    }
    /// <summary>
    /// Updates policy module flags by writing them to Certification Authority.
    /// </summary>
    /// <param name="restart">
    /// Indicates whether to restart certificate services to immediately apply changes. Updated settings has no effect
    /// until CA service is restarted.
    /// </param>
    /// <exception cref="UnauthorizedAccessException">
    /// The caller do not have sufficient permissions to make changes in the CA configuration.
    /// </exception>
    /// <exception cref="ServerUnavailableException">
    /// The target CA server could not be contacted via remote registry and RPC protocol.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
    /// and the method returns <strong>False</strong>.
    /// </returns>
    /// <remarks>The caller must have <strong>Administrator</strong> permissions on the target CA server.</remarks>
    public Boolean SetInfo(Boolean restart) {
        if (IsModified) {
            if (CryptoRegistry.Ping(ComputerName)) {
                CryptoRegistry.SetRReg((Int32)EditFlags, "EditFlags", RegistryValueKind.DWord, $@"{Name}\PolicyModules\{activePolicyModule}", ComputerName);
                if (restart) { CertificateAuthority.Restart(ComputerName); }
                IsModified = false;
                return true;
            }
            if (CertificateAuthority.Ping(ComputerName)) {
                CryptoRegistry.SetRegFallback(configString, $@"PolicyModules\{activePolicyModule}", "EditFlags", (Int32)EditFlags);
                if (restart) { CertificateAuthority.Restart(ComputerName); }
                IsModified = false;
                return true;
            }
            ServerUnavailableException e = new ServerUnavailableException(DisplayName);
            e.Data.Add(nameof(e.Source), (OfflineSource)3);
            throw e;
        }
        return false;
    }
}
