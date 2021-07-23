using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Interop.CERTENROLLLib;
using PKI.Utils;
using SysadminsLV.PKI.Security.AccessControl;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace PKI.CertificateTemplates {
    /// <summary>
    /// Represents a certificate template object.
    /// </summary>
    public class CertificateTemplate {
        Int32 major, minor, flags;
        static readonly String _baseDsPath = $"CN=Certificate Templates, CN=Public Key Services, CN=Services,{DsUtils.ConfigContext}";

        internal CertificateTemplate(IX509CertificateTemplate template) {
            initializeCom(template);
            Settings = new CertificateTemplateSettings(template);
        }
        /// <param name="name">Specifies the certificate template name.</param>
        [Obsolete("Use 'CertificateTemplate.FromCommonName()' method instead.")]
        public CertificateTemplate(String name) : this("Name", name) { }
        /// <param name="findType">
        /// Specifies certificate template search type. The search type can be either:
        /// Name, DisplayName or OID.
        /// </param>
        /// <param name="findValue">
        /// Specifies search pattern for a type specified in <strong>findType</strong> argument.
        /// </param>
        /// <remarks>Wildcards are not allowed.</remarks>
        [Obsolete("Use appropriate static factory method instead.")]
        public CertificateTemplate(String findType, String findValue) {
            if (!DsUtils.Ping()) {
                throw new Exception(Error.E_DCUNAVAILABLE);
            }
            m_initialize(findType, findValue);
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
        public Boolean AutoenrollmentAllowed => SchemaVersion > 1 && (flags & (Int32)CertificateTemplateFlags.Autoenrollment) > 0;

        /// <summary>
        /// Gets certificate template's object identifier. Object identifiers are used to uniquely identify certificate template. While
        /// certificate template common and display names can be changed, OID remains the same. Once template is deleted from
        /// Active Directory, associated OID is removed too. Any new template (even if with the same name values) will have differen
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
        /// </list></description>
        /// </item>
        /// <item><term>2</term>
        /// <description><list type="bullet">
        /// <item>Windows Server 2003 Enterprise, Datacenter editions</item>
        /// <item>Windows Server 2008 Enterprise, Datacenter editions</item>
        /// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
        /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
        /// </list></description>
        /// </item>
        /// <item><term>3</term>
        /// <description><list type="bullet">
        /// <item>Windows Server 2008 Enterprise, Datacenter editions</item>
        /// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
        /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
        /// </list></description>
        /// </item>
        /// <item><term>4</term>
        /// <description><list type="bullet">
        /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
        /// </list></description>
        /// </item>
        /// </list>
        /// </summary>
        public String SupportedCA {
            get {
                switch (SchemaVersion) {
                    case 1: return "Windows 2000 Server";
                    case 2: return "Windows Server 2003 Enterprise Edition";
                    case 3: return "Windows Server 2008 Enterprise Edition";
                    case 4: return "Windows Server 2012";
                    default: return null;
                }
            }
        }
        /// <summary>
        /// Gets or sets certificate template extended settings.
        /// </summary>
        public CertificateTemplateSettings Settings { get; private set; }

        void m_initialize(String findType, String findValue) {
            String cn = String.Empty;
            switch (findType.ToLower()) {
                case "name":
                    cn = $"CN={escapeChars(findValue)},{_baseDsPath}";
                    break;
                case "displayname":
                    cn = DsUtils.Find(_baseDsPath, DsUtils.PropDisplayName, findValue);
                    break;
                case "oid":
                    cn = DsUtils.Find(_baseDsPath, DsUtils.PropCertTemplateOid, findValue);
                    break;
                default: throw new Exception("The value for 'findType' must be either 'Name', 'DisplayName' or 'OID'.");
            }
            m_fillproperties(cn);
        }
        void m_fillproperties(String ldapPath) {
            IDictionary<String, Object> props = DsUtils.GetEntryProperties(
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
            flags = (Int32)props[DsUtils.PropFlags];
            Name = (String)props[DsUtils.PropCN];
            DistinguishedName = (String) props[DsUtils.PropDN];
            DisplayName = (String)props[DsUtils.PropDisplayName];
            major = (Int32) props[DsUtils.PropPkiTemplateMajorVersion];
            minor = (Int32) props[DsUtils.PropPkiTemplateMinorVersion];
            SchemaVersion = (Int32) props[DsUtils.PropPkiSchemaVersion];
            OID = new Oid((String) props[DsUtils.PropCertTemplateOid]);
            LastWriteTime = (DateTime) props[DsUtils.PropWhenChanged];
            Settings = new CertificateTemplateSettings(props);
        }
        void initializeCom(IX509CertificateTemplate template) {
            Name = (String)template.Property[EnrollmentTemplateProperty.TemplatePropCommonName];
            DisplayName = (String)template.Property[EnrollmentTemplateProperty.TemplatePropFriendlyName];
            OID = new Oid(((IObjectId)template.Property[EnrollmentTemplateProperty.TemplatePropOID]).Value);
            if (CryptographyUtils.TestOleCompat()) {
                major = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropMajorRevision];
                minor = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropMinorRevision];
                SchemaVersion = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropSchemaVersion];
            } else {
                major = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropMajorRevision]);
                minor = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropMinorRevision]);
                SchemaVersion = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropSchemaVersion]);
            }
        }
        static String escapeChars(String inputStr) {
            return inputStr
                .Replace(@"\", @"\\")
                .Replace(",", @"\,")
                .Replace("/",@"\/")
                .Replace("#", @"\#")
                .Replace("+", @"\+")
                .Replace("<", @"\<")
                .Replace(">", @"\>")
                .Replace(";", @"\;")
                .Replace("\"", "\\\"")
                .Replace("=", @"\=");
        }

        /// <summary>
        /// Enumerates certificate templates registered in Active Directory.
        /// </summary>
        /// <returns>An array of certificate templates.</returns>
        public static CertificateTemplate[] EnumTemplates() {
            if (!DsUtils.Ping()) {
                throw new Exception(Error.E_DCUNAVAILABLE);
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
            return ReferenceEquals(this, other) || Equals((CertificateTemplate) other);
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
            return String.Equals(Name, other.Name) && OID.Equals2(other.OID);
        }
        /// <summary>
        /// Serves as a hash function for a particular type.
        /// </summary>
        /// <returns>The hash code for the certificate template as an integer.</returns>
        public override Int32 GetHashCode() {
            unchecked { return (Name.GetHashCode() * 397) ^ OID.GetHashCode2(); }
        }
        /// <summary>
        /// Gets access control list (security descriptor) of the current certificate template.
        /// </summary>
        /// <returns>Security descriptor.</returns>
        public CertTemplateSecurityDescriptor GetSecurityDescriptor() {
            return new CertTemplateSecurityDescriptor(this);
        }
        /// <summary>
        /// Gets certificate template textual representation.
        /// </summary>
        /// <returns>Certificate template textual representation.</returns>
        public String Format() {
            String nl = Environment.NewLine;
            StringBuilder SB = new StringBuilder();
            SB.Append($"[General Settings]{nl}");
            SB.Append($"  Common name: {Name}{nl}");
            SB.Append($"  Display name: {DisplayName}{nl}");
            SB.Append($"  Version: {Version}{nl}");
            SB.Append($"  Supported CA: {SupportedCA}{nl}");
            SB.Append($"  Subject type: {Settings.SubjectType}{nl}");
            SB.Append((Settings.EnrollmentOptions & (Int32) CertificateTemplateEnrollmentFlags.DsPublish) > 0
                ? $"  Publish to DS: True{nl}"
                : $"  Publish to DS: False{nl}");
            SB.Append((Settings.EnrollmentOptions & (Int32) CertificateTemplateEnrollmentFlags.AutoenrollmentCheckDsCert) > 0
                ? $"  Check for existing certificate in DS: True{nl}"
                : $"  Check for existing certificate in DS: False{nl}");
            SB.Append((Settings.EnrollmentOptions & (Int32) CertificateTemplateEnrollmentFlags.ReuseKeyTokenFull) > 0
                ? $"  Reuse key when tokein is full: True{nl}"
                : $"  Reuse key when tokein is full: False{nl}");
            SB.Append($"[Subject]{nl}");
            SB.Append($"  {Settings.SubjectName}{nl}");
            SB.Append(Settings.Cryptography + nl);
            SB.Append(Settings.RegistrationAuthority + nl);
            SB.Append(Settings.KeyArchivalSettings + nl);
            SB.Append($"[Superseded Templates]{nl}");
            if (Settings.SupersededTemplates.Length == 0) {
                SB.Append($"  None{nl}");
            } else {
                foreach(String template in Settings.SupersededTemplates) {
                    SB.Append($"  {template}{nl}");
                }
            }
            SB.Append($"[Extensions]{nl}");
            foreach (X509Extension ext in Settings.Extensions) {
                SB.Append($"  Extension name:{nl}    {ext.Oid.FriendlyName}{nl}");
                SB.Append($"  Extension value:{nl}    {ext.Format(true).Replace("\r\n","\r\n    ")}{nl}");
            }
            SB.Append(nl);
            return SB.ToString();
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
}
