using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Interop.CERTENROLLLib;
using SysadminsLV.PKI.Management.ActiveDirectory;
using SysadminsLV.PKI.Security.AccessControl;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateTemplates;

/// <summary>
/// Represents a certificate template object.
/// </summary>
public class CertificateTemplate {
    Int32 major, minor, flags;
    static readonly String _baseDsPath = $"CN=Certificate Templates, CN=Public Key Services, CN=Services,{DsUtils.ConfigContext}";

    internal CertificateTemplate(IX509CertificateTemplate template) {
        initializeFromCom(template);
        Settings = new CertificateTemplateSettings(template);
    }
    /// <param name="findType">
    /// Specifies certificate template search type. The search type can be either:
    /// Name, DisplayName or OID.
    /// </param>
    /// <param name="findValue">
    /// Specifies search pattern for a type specified in <strong>findType</strong> argument.
    /// </param>
    /// <remarks>Wildcards are not allowed.</remarks>
    CertificateTemplate(String findType, String findValue) {
        if (!DsUtils.Ping()) {
            throw new Exception(ErrorHelper.E_DCUNAVAILABLE);
        }
        searchByQuery(findType, findValue);
    }

    /// <summary>
    /// Gets certificate template common name. Common names cannot contain the following characters: " + , ; &lt; = &gt;
    /// </summary>
    public String Name { get; private set; }
    /// <summary>
    /// Gets certificate template display name. Display name has no character restrictions.
    /// </summary>
    public String DisplayName { get; private set; }
    /// <summary>
    /// Gets certificate template internal version. The version consist of two values separated by dot: major version and minor version.
    /// Any template changes causes internal version change.
    /// </summary>
    /// <remarks>Template internal version is not changed if you modify template ACL only.</remarks>
    public String Version => $"{major}.{minor}";

    /// <summary>
    /// Gets certificate template schema version (also known as template version). The value can be either 1, 2, 3 or 4. For template support
    /// by CA version see <see cref="SupportedCA"/> property description.
    /// </summary>
    public Int32 SchemaVersion { get; private set; }
    /// <summary>
    /// This flag indicates whether clients can perform autoenrollment for the specified template.
    /// </summary>
    public Boolean AutoenrollmentAllowed => SchemaVersion > 1 && (flags & (Int32)CertificateTemplateFlags.Autoenrollment) != 0;

    /// <summary>
    /// Gets certificate template's object identifier. Object identifiers are used to uniquely identify certificate template. While
    /// certificate template common and display names can be changed, OID remains the same. Once template is deleted from
    /// Active Directory, associated OID is removed too. Any new template (even if with the same name values) will have different
    /// OID value.
    /// </summary>
    public Oid OID { get; private set; }
    /// <summary>
    /// Gets the timestamp when certificate template was edited last time. The value can be used for audit purposes.
    /// </summary>
    public DateTime LastWriteTime { get; private set; }
    /// <summary>
    /// Gets certificate template's full distinguished name (location address) in Active Directory.
    /// </summary>
    public String DistinguishedName { get; private set; }
    /// <summary>
    /// Gets the minimum version of the Certification Authority that can use this template to issue certificates. The following table
    /// describes template support by CA version:
    /// <list type="table">
    /// <listheader>
    /// <term>Schema version</term>
    /// <description>Supported CA versions</description>
    /// </listheader>
    /// <item><term>1</term>
    /// <description><list type="bullet">
    /// <item>Windows 2000 Server</item>
    /// <item>Windows Server 2003 Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2016 Standard, Datacenter editions</item>
    /// <item>Windows Server 2019 Standard, Datacenter editions</item>
    /// <item>Windows Server 2022 Standard, Datacenter editions</item>
    /// </list></description>
    /// </item>
    /// <item><term>2</term>
    /// <description><list type="bullet">
    /// <item>Windows Server 2003 Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2016 Standard, Datacenter editions</item>
    /// <item>Windows Server 2019 Standard, Datacenter editions</item>
    /// <item>Windows Server 2022 Standard, Datacenter editions</item>
    /// </list></description>
    /// </item>
    /// <item><term>3</term>
    /// <description><list type="bullet">
    /// <item>Windows Server 2008 Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2016 Standard, Datacenter editions</item>
    /// <item>Windows Server 2019 Standard, Datacenter editions</item>
    /// <item>Windows Server 2022 Standard, Datacenter editions</item>
    /// </list></description>
    /// </item>
    /// <item><term>4</term>
    /// <description><list type="bullet">
    /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2016 Standard, Datacenter editions</item>
    /// <item>Windows Server 2019 Standard, Datacenter editions</item>
    /// <item>Windows Server 2022 Standard, Datacenter editions</item>
    /// </list></description>
    /// </item>
    /// </list>
    /// </summary>
    public String SupportedCA { get; private set; }
    /// <summary>
    /// Gets the minimum supported client that can enroll certificates based on this template.
    /// </summary>
    public String SupportedClient { get; private set; }
    /// <summary>
    /// Gets or sets certificate template extended settings.
    /// </summary>
    public CertificateTemplateSettings Settings { get; private set; }

    void searchByQuery(String findType, String findValue) {
        String dn         = findType.ToLower() switch {
            "name"        => DsUtils.Find(_baseDsPath, DsUtils.PropCN, findValue),
            "displayname" => DsUtils.Find(_baseDsPath, DsUtils.PropDisplayName, findValue),
            "oid"         => DsUtils.Find(_baseDsPath, DsUtils.PropCertTemplateOid, findValue),
            _             => throw new Exception("The value for 'findType' must be either 'Name', 'DisplayName' or 'OID'.")
        };

        if (String.IsNullOrWhiteSpace(dn)) {
            throw new ArgumentException("No certificate templates match search criteria.");
        }
        
        initializeFromDs(dn);
    }
    void initializeFromDs(String ldapPath) {
        DsPropertyCollection props = DsUtils.GetEntryProperties(
            ldapPath,
            DsUtils.PropCN,
            DsUtils.PropDN,
            DsUtils.PropDisplayName,
            DsUtils.PropFlags,
            DsUtils.PropCpsOid,
            DsUtils.PropCertTemplateOid,
            DsUtils.PropLocalizedOid,
            DsUtils.PropPkiTemplateMajorVersion,
            DsUtils.PropPkiTemplateMinorVersion,
            DsUtils.PropPkiSchemaVersion,
            DsUtils.PropWhenChanged,
            DsUtils.PropPkiSubjectFlags,
            DsUtils.PropPkiEnrollFlags,
            DsUtils.PropPkiPKeyFlags,
            DsUtils.PropPkiNotAfter,
            DsUtils.PropPkiRenewalPeriod,
            DsUtils.PropPkiPathLength,
            DsUtils.PropCertTemplateEKU,
            DsUtils.PropPkiCertPolicy,
            DsUtils.PropPkiCriticalExt,
            DsUtils.PropPkiSupersede,
            DsUtils.PropPkiKeyCsp,
            DsUtils.PropPkiKeySize,
            DsUtils.PropPkiKeySpec,
            DsUtils.PropPkiKeySddl,
            DsUtils.PropPkiRaAppPolicy,
            DsUtils.PropPkiRaCertPolicy,
            DsUtils.PropPkiRaSignature,
            DsUtils.PropPkiAsymAlgo,
            DsUtils.PropPkiSymAlgo,
            DsUtils.PropPkiSymLength,
            DsUtils.PropPkiHashAlgo,
            DsUtils.PropPkiKeyUsage,
            DsUtils.PropPkiKeyUsageCng
        );
        flags = props.GetDsScalarValue<Int32>(DsUtils.PropFlags);
        Name = props.GetDsScalarValue<String>(DsUtils.PropCN);
        DistinguishedName = ldapPath.Replace("LDAP://", null); // we have to use ldapPath, because it is fully escaped and re-usable. DN is not.
        DisplayName = props.GetDsScalarValue<String>(DsUtils.PropDisplayName);
        major = props.GetDsScalarValue<Int32>(DsUtils.PropPkiTemplateMajorVersion);
        minor = props.GetDsScalarValue<Int32>(DsUtils.PropPkiTemplateMinorVersion);
        SchemaVersion = props.GetDsScalarValue<Int32>(DsUtils.PropPkiSchemaVersion);
        OID = new Oid(props.GetDsScalarValue<String>(DsUtils.PropCertTemplateOid));
        LastWriteTime = props.GetDsScalarValue<DateTime>(DsUtils.PropWhenChanged);
        Settings = new CertificateTemplateSettings(props);

        setClientSupport(props.GetDsScalarValue<PrivateKeyFlags>(DsUtils.PropPkiPKeyFlags));
        setServerSupport(props.GetDsScalarValue<PrivateKeyFlags>(DsUtils.PropPkiPKeyFlags));
    }
    void setClientSupport(PrivateKeyFlags pkFlags) {
        const Int32 mask = 0x0F000000;
        PrivateKeyFlags result = pkFlags & (PrivateKeyFlags)mask;

        SupportedClient                  = result switch {
            PrivateKeyFlags.None         => getClientSupportLegacy(),
            PrivateKeyFlags.Client2003   => "Windows XP",
            PrivateKeyFlags.Client2008   => "Windows Vista",
            PrivateKeyFlags.Client2008R2 => "Windows 7",
            PrivateKeyFlags.Client2012   => "Windows 8",
            PrivateKeyFlags.Client2012R2 => "Windows 8.1",
            PrivateKeyFlags.Client2016R2 => "Windows 10",
            _                            => "Unknown"
        };
    }
    String getClientSupportLegacy() {
        return SchemaVersion switch {
            1 => "Windows 2000",
            2 => "Windows XP",
            3 => "Windows Vista",
            4 => "Windows 8",
            _ => "Unknown"
        };
    }
    void setServerSupport(PrivateKeyFlags pkFlags) {
        const Int32 mask = 0x000F0000;
        PrivateKeyFlags result = pkFlags & (PrivateKeyFlags)mask;

        SupportedCA                      = result switch {
            PrivateKeyFlags.None         => getServerSupportLegacy(),
            PrivateKeyFlags.Server2003   => "Windows Server 2003",
            PrivateKeyFlags.Server2008   => "Windows Server 2008",
            PrivateKeyFlags.Server2008R2 => "Windows Server 2008 R2",
            PrivateKeyFlags.Server2012   => "Windows Server 2012",
            PrivateKeyFlags.Server2012R2 => "Windows Server 2012 R2",
            PrivateKeyFlags.Server2016R2 => "Windows Server 2016",
            _                            => "Unknown"
        };
    }
    String getServerSupportLegacy() {
        return SchemaVersion switch {
            1 => "Windows 2000 Server",
            2 => "Windows Server 2003 Enterprise Edition",
            3 => "Windows Server 2008 Enterprise Edition",
            4 => "Windows Server 2012",
            _ => "Unknown"
        };
    }
    void initializeFromCom(IX509CertificateTemplate template) {
        Name = (String)template.Property[EnrollmentTemplateProperty.TemplatePropCommonName];
        DisplayName = (String)template.Property[EnrollmentTemplateProperty.TemplatePropFriendlyName];
        OID = new Oid(((IObjectId)template.Property[EnrollmentTemplateProperty.TemplatePropOID]).Value);
        // we use Convert.ToInt32, because COM variants can be either signed or unsigned integer based on a platform.
        major = Convert.ToInt32(template.Property[EnrollmentTemplateProperty.TemplatePropMajorRevision]);
        minor = Convert.ToInt32(template.Property[EnrollmentTemplateProperty.TemplatePropMinorRevision]);
        SchemaVersion = Convert.ToInt32(template.Property[EnrollmentTemplateProperty.TemplatePropSchemaVersion]);
        Settings = new CertificateTemplateSettings(template);
        setClientSupport((PrivateKeyFlags)Convert.ToInt32(template.Property[EnrollmentTemplateProperty.TemplatePropPrivateKeyFlags]));
        setServerSupport((PrivateKeyFlags)Convert.ToInt32(template.Property[EnrollmentTemplateProperty.TemplatePropPrivateKeyFlags]));
    }

    /// <summary>
    /// Enumerates certificate templates registered in Active Directory.
    /// </summary>
    /// <returns>An array of certificate templates.</returns>
    public static CertificateTemplate[] EnumTemplates() {
        if (!DsUtils.Ping()) {
            throw new Exception(ErrorHelper.E_DCUNAVAILABLE);
        }

        var retValue = new List<CertificateTemplate>();
        foreach (DirectoryEntry dsEntry in DsUtils.GetChildItems(_baseDsPath)) {
            using (dsEntry) {
                retValue.Add(FromCommonName(dsEntry.Properties["cn"].Value.ToString()));
            }
        }
        return retValue.ToArray();
    }

    /// <summary>
    /// Compares two <strong>CertificateTemplate</strong> objects for equality.
    /// </summary>
    /// <param name="other">An <strong>CertificateTemplate</strong> object to compare to the current object.</param>
    /// <returns>
    /// <strong>True</strong> if the current <strong>CertificateTemplate</strong> object is equal to the object specified by the other parameter;
    /// otherwise, <strong>False</strong>.
    /// </returns>
    /// <remarks>
    /// Two objects are considered equal if they are <strong>CertificateTemplate</strong> objects and they have the same
    /// name and OID values.
    /// </remarks>
    public override Boolean Equals(Object other) {
        if (ReferenceEquals(null, other) || other.GetType() != GetType()) { return false; }
        return ReferenceEquals(this, other) || Equals((CertificateTemplate)other);
    }
    /// <summary>
    /// Compares two <strong>CertificateTemplate</strong> objects for equality.
    /// </summary>
    /// <param name="other">An <strong>CertificateTemplate</strong> object to compare to the current object.</param>
    /// <returns>
    /// <strong>True</strong> if the current <strong>CertificateTemplate</strong> object is equal to the object specified by the other parameter;
    /// otherwise, <strong>False</strong>.
    /// </returns>
    /// <remarks>
    /// Two objects are considered equal if they are <strong>CertificateTemplate</strong> objects and they have the same
    /// name and OID values.
    /// </remarks>
    protected Boolean Equals(CertificateTemplate other) {
        return String.Equals(Name, other.Name) && OID?.Value == other.OID?.Value;
    }
    /// <summary>
    /// Serves as a hash function for a particular type.
    /// </summary>
    /// <returns>The hash code for the certificate template as an integer.</returns>
    public override Int32 GetHashCode() {
        unchecked { return (Name.GetHashCode() * 397) ^ OID?.Value.GetHashCode() ?? 0; }
    }
    /// <summary>
    /// Gets access control list (security descriptor) of the current certificate template.
    /// </summary>
    /// <returns>Security descriptor.</returns>
    public CertTemplateSecurityDescriptor GetSecurityDescriptor() {
        return new CertTemplateSecurityDescriptor(this);
    }
    /// <summary>
    /// Gets template major version. Major version is used by autoenrollment component to determine if certificate
    /// needs to be renewed prior to scheduled renewal period.
    /// </summary>
    /// <returns>Template major version.</returns>
    public Int32 GetMajorVersion() {
        return major;
    }
    /// <summary>
    /// Gets template minor version. Minor version is increased with every template setting change
    /// (excluding ACL, common and display names) and used by autoenrollment component to determine whether to use
    /// new or renewal request during re-enrollment.
    /// </summary>
    /// <returns>Template minor version.</returns>
    public Int32 GetMinorVersion() {
        return minor;
    }
    /// <summary>
    /// Gets certificate template textual representation.
    /// </summary>
    /// <returns>Certificate template textual representation.</returns>
    public String Format() {
        var SB = new StringBuilder();
        SB.AppendLine(@$"
[General Settings]
  Common name: {Name}
  Display name: {DisplayName}
  Version: {Version}
  Supported CA: {SupportedCA}
  Subject type: {Settings.SubjectType}
  Publish to DS: {(Settings.EnrollmentOptions & CertificateTemplateEnrollmentFlags.DsPublish) != 0}
  Check for existing certificate in DS: {(Settings.EnrollmentOptions & CertificateTemplateEnrollmentFlags.AutoenrollmentCheckDsCert) != 0}
  Reuse key when token is full: {(Settings.EnrollmentOptions & CertificateTemplateEnrollmentFlags.ReuseKeyTokenFull) != 0}
[Subject]
  {Settings.SubjectName}
{Settings.Cryptography}
{Settings.RegistrationAuthority}
{Settings.KeyArchivalSettings}
[Superseded Templates]");
        if (Settings.SupersededTemplates.Length == 0) {
            SB.AppendLine("  None");
        } else {
            foreach (String template in Settings.SupersededTemplates) {
                SB.AppendLine($"  {template}");
            }
        }
        SB.AppendLine("[Extensions]");
        foreach (X509Extension ext in Settings.Extensions) {
            SB.AppendLine(@$"  Extension name:
    {ext.Oid.FriendlyName}
  Extension value:
    {ext.Format(true).TrimEnd().Replace("\r\n", "\r\n    ")}");
        }

        return SB.ToString().Trim();
    }

    /// <summary>
    /// Creates a new instance of <strong>CertificateTemplate</strong> object from certificate template's common name.
    /// </summary>
    /// <param name="cn">Certificate template's common name.</param>
    /// <returns>Certificate template object.</returns>
    public static CertificateTemplate FromCommonName(String cn) {
        return new CertificateTemplate("Name", cn);
    }
    /// <summary>
    /// Creates a new instance of <strong>CertificateTemplate</strong> object from certificate template's display name.
    /// </summary>
    /// <param name="displayName">Certificate template's display/friendly name.</param>
    /// <returns>Certificate template object.</returns>
    public static CertificateTemplate FromDisplayName(String displayName) {
        return new CertificateTemplate("DisplayName", displayName);
    }
    /// <summary>
    /// Creates a new instance of <strong>CertificateTemplate</strong> object from certificate template's object identifier (OID).
    /// </summary>
    /// <param name="oid">Certificate template's dot-decimal object identifier.</param>
    /// <returns>Certificate template object.</returns>
    public static CertificateTemplate FromOid(String oid) {
        return new CertificateTemplate("OID", oid);
    }
}