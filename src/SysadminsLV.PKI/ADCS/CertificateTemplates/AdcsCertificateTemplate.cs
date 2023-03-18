using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.ADCS.CertificateTemplates;

/// <summary>
/// Represents Microsoft AD CS decoded certificate template.
/// </summary>
public class AdcsCertificateTemplate {
    readonly Int32 _majorRevision;
    readonly Int32 _minorRevision;
    readonly CertificateTemplateFlags _flags;

    public AdcsCertificateTemplate(IAdcsCertificateTemplate template) {
        if (template == null) {
            throw new ArgumentNullException(nameof(template));
        }

        Name = template.CommonName;
        DisplayName = template.DisplayName;
        _majorRevision = template.MajorVersion;
        _minorRevision = template.MinorVersion;
        _flags = template.Flags;
        SchemaVersion = template.SchemaVersion;
        OID = new Oid(template.Oid, DisplayName);
        if (template.ExtendedProperties.ContainsKey("LastWriteTime")) {
            LastWriteTime = template.ExtendedProperties["LastWriteTime"] as DateTime?;
        }
        if (template.ExtendedProperties.ContainsKey("DistinguishedName")) {
            DistinguishedName = template.ExtendedProperties["DistinguishedName"] as String;
        }
    }

    /// <summary>
    /// Gets certificate template common name. Common names cannot contain the following characters: " + , ; &lt; = &gt;
    /// </summary>
    public String Name { get; }
    /// <summary>
    /// Gets certificate template display name. Display name has no character restrictions.
    /// </summary>
    public String DisplayName { get; }
    /// <summary>
    /// Gets certificate template internal version. The version consist of two values separated by dot: major version and minor version.
    /// Any template changes causes internal version change.
    /// </summary>
    /// <remarks>Template internal version is not changed if you modify template ACL only.</remarks>
    public String Version => $"{_majorRevision}.{_minorRevision}";

    /// <summary>
    /// Gets certificate template schema version (also known as template version). The value can be either 1, 2, 3 or 4. For template support
    /// by CA version see <see cref="SupportedCA"/> property description.
    /// </summary>
    public Int32 SchemaVersion { get; private set; }
    /// <summary>
    /// This flag indicates whether clients can perform autoenrollment for the specified template.
    /// </summary>
    public Boolean AutoenrollmentAllowed => SchemaVersion > 1 && (_flags & CertificateTemplateFlags.Autoenrollment) > 0;

    /// <summary>
    /// Gets certificate template's object identifier. Object identifiers are used to uniquely identify certificate template. While
    /// certificate template common and display names can be changed, OID remains the same. Once template is deleted from
    /// Active Directory, associated OID is removed too. Any new template (even if with the same name values) will have different
    /// OID value.
    /// </summary>
    public Oid OID { get; }
    /// <summary>
    /// Gets the timestamp when certificate template was edited last time. The value can be used for audit purposes.
    /// </summary>
    public DateTime? LastWriteTime { get; private set; }
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
}
