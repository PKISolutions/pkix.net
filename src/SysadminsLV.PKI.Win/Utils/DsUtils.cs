using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Management.ActiveDirectory;

namespace SysadminsLV.PKI.Utils;

static class DsUtils {
    public const String PropConfigNameContext       = "ConfigurationNamingContext";
    public const String PropSiteObject              = "siteObject";
    public const String PropPkiEnrollmentServers    = "msPKI-Enrollment-Servers";
    public const String PropCN                      = "cn";
    public const String PropDN                      = "distinguishedName";
    public const String PropDisplayName             = "displayName";
    public const String PropDescription             = "description";
    public const String PropFlags                   = "flags";
    public const String PropCpsOid                  = "msPKI-OID-CPS";
    public const String PropCertTemplateOid         = "msPKI-Cert-Template-OID";
    public const String PropLocalizedOid            = "msPKI-OIDLocalizedName";
    public const String PropPkiTemplateMajorVersion = "Revision";
    public const String PropPkiTemplateMinorVersion = "msPKI-Template-Minor-Revision";
    public const String PropPkiSchemaVersion        = "msPKI-Template-Schema-Version";
    public const String PropWhenChanged             = "WhenChanged";
    public const String PropPkiSubjectFlags         = "msPKI-Certificate-Name-Flag";
    public const String PropPkiEnrollFlags          = "msPKI-Enrollment-Flag";
    public const String PropPkiPKeyFlags            = "msPKI-Private-Key-Flag";
    public const String PropPkiNotAfter             = "pKIExpirationPeriod";
    public const String PropPkiRenewalPeriod        = "pKIOverlapPeriod";
    public const String PropPkiPathLength           = "pKIMaxIssuingDepth";
    public const String PropCertTemplateEKU         = "pKIExtendedKeyUsage";
    public const String PropPkiCertPolicy           = "msPKI-Certificate-Policy";
    public const String PropPkiCriticalExt          = "pKICriticalExtensions";
    public const String PropPkiSupersede            = "msPKI-Supersede-Templates";
    public const String PropPkiKeyCsp               = "pKIDefaultCSPs";
    public const String PropPkiKeySize              = "msPKI-Minimal-Key-Size";
    public const String PropPkiKeySpec              = "pKIDefaultKeySpec";
    public const String PropPkiKeySddl              = "msPKI-Key-Security-Descriptor";
    public const String PropPkiRaAppPolicy          = "msPKI-RA-Application-Policies";
    public const String PropPkiRaCertPolicy         = "msPKI-RA-Policies";
    public const String PropPkiRaSignature          = "msPKI-RA-Signature";
    public const String PropPkiAsymAlgo             = "msPKI-Asymmetric-Algorithm";
    public const String PropPkiSymAlgo              = "msPKI-Symmetric-Algorithm";
    public const String PropPkiSymLength            = "msPKI-Symmetric-Key-Length";
    public const String PropPkiHashAlgo             = "msPKI-Hash-Algorithm";
    public const String PropPkiKeyUsage             = "pKIKeyUsage";
    public const String PropPkiKeyUsageCng          = "msPKI-Key-Usage";

    public const String SchemaObjectIdentifier = "msPKI-Enterprise-Oid";


    const String disallowed = @"!""#%&'()*+,/:;<=>?[\]^`{|}";

    public static String ConfigContext {
        get {
            using var entry = new DirectoryEntry("LDAP://RootDSE");
            if (Ping()) {
                return (String)entry.Properties[PropConfigNameContext].Value;
            }
            return null;
        }
    }
    public static String GetCurrentForestName() {
        return GetComputerForestName();
    }
    public static String GetComputerForestName() {
        return Ping()
            ? Domain.GetComputerDomain().Forest.Name
            : String.Empty;
    }
    public static String GetCurrentDomainName() {
        return Ping()
            ? Domain.GetComputerDomain().Name
            : String.Empty;
    }
    public static String GetComputerDomainName() {
        return GetCurrentDomainName();
    }
    public static String GetUserDomainName() {
        return Ping()
            ? Domain.GetComputerDomain().Name
            : String.Empty;
    }
    public static Object GetEntryProperty(String ldapPath, String prop) {
        using var entry = new DirectoryEntry($"LDAP://{escapeLdapPath(ldapPath)}");
        return entry.Properties.Contains(prop)
            ? entry.Properties[prop].Value
            : null;
    }
    public static DsPropertyCollection GetEntryProperties(String ldapPath, params String[] properties) {
        var retValue = new DsPropertyCollection();
        using var entry = new DirectoryEntry($"LDAP://{escapeLdapPath(ldapPath)}");
        foreach (String prop in properties) {
            retValue.Add(prop, entry.Properties.Contains(prop)
                ? entry.Properties[prop].Value
                : null);
        }

        return retValue;
    }
    /// <summary>
    /// Adds child entry to DS container.
    /// </summary>
    /// <param name="ldapPath">DS path to container object to add child to.</param>
    /// <param name="name">Child common name.</param>
    /// <param name="schemaClass">Child schema class.</param>
    /// <returns>DS path to created child.</returns>
    public static String AddChildEntry(String ldapPath, String name, String schemaClass) {
        using var entry = new DirectoryEntry($"LDAP://{escapeLdapPath(ldapPath)}");
        using DirectoryEntry newEntry = entry.Children.Add(EscapeChars(name), schemaClass);
        newEntry.CommitChanges();

        return (String)newEntry.Properties[PropDN].Value;
    }
    /// <summary>
    /// Removes child entry from DS container.
    /// </summary>
    /// <param name="ldapPath">Child's DS path to remove.</param>
    public static void RemoveChildEntry(String ldapPath) {
        using var entryToDelete = new DirectoryEntry($"LDAP://{escapeLdapPath(ldapPath)}");
        using DirectoryEntry parent = entryToDelete.Parent;
        parent.Children.Remove(entryToDelete);
        parent.CommitChanges();
    }
    public static void SetEntryProperty(String ldapPath, String prop, Object value) {
        using var entry = new DirectoryEntry($"LDAP://{escapeLdapPath(ldapPath)}");
        entry.Properties[prop].Value = value;
        entry.CommitChanges();
    }
    public static String Find(String searchRoot, String propName, String propValue) {
        using var entry = new DirectoryEntry($"LDAP://{escapeLdapPath(searchRoot)}");
        using var searcher = new DirectorySearcher(entry);
        searcher.Filter = $"{propName}={EscapeChars(propValue)}";

        return (String)searcher.FindOne()?.GetDirectoryEntry().Properties[PropDN].Value;
    }
    public static Boolean Ping() {
        try {
            String domain = Domain.GetComputerDomain().Name;
            return !String.IsNullOrEmpty(domain);
        } catch { return false; }
    }
    public static DirectoryEntries GetChildItems(String ldap) {
        return new DirectoryEntry($"LDAP://{escapeLdapPath(ldap)}").Children;
    }
    public static String BindServerToSite(String computerName) {
        if (String.IsNullOrEmpty(computerName)) {
            return null;
        }
        var siteTable = new Dictionary<String, String>();
        IPHostEntry ip = Dns.GetHostEntry(computerName);

        try {
            using var subnets = new DirectoryEntry($"LDAP://CN=Subnets,CN=Sites,{ConfigContext}");
            foreach (DirectoryEntry subnet in subnets.Children) {
                using var site = new DirectoryEntry("LDAP://" + subnet.Properties[PropSiteObject].Value);
                siteTable.Add(subnet.Properties[PropCN].Value.ToString(), site.Properties[PropCN].Value.ToString());
            }
        } catch {
            return null;
        }
        foreach (String key in siteTable.Keys) {
            String[] tokens = key.Split('/');
            if (ip.AddressList.Any(address => NetUtils.InSameSubnet(tokens[0], Convert.ToInt32(tokens[1]), address.ToString()))) {
                return siteTable[key];
            }
        }
        return null;
    }

    static String escapeLdapPath(String ldapPath) {
        var sb = new StringBuilder();
        X500RdnAttributeCollection rdns = new X500DistinguishedName(ldapPath).GetRdnAttributes();
        for (Int32 index = 1; index < rdns.Count; index++) {
            X500RdnAttribute old = rdns[index];
            sb.AppendFormat(",{0}={1}", old.Oid.FriendlyName, old.Value);
        }

        sb.Insert(0, $"CN={EscapeChars(rdns[0].Value)}");

        return sb.ToString();
    }
    // see: http://msdn.microsoft.com/en-us/library/aa746475.aspx
    public static String EscapeChars(String inputStr) {
        return inputStr
            // replace with backslash and ASCII code (in hex)
            .Replace("*", @"\2a")
            .Replace("(", @"\28")
            .Replace(")", @"\29")
            .Replace("\\", @"\5c")
            .Replace("\0", @"\00")
            .Replace("/", @"\2f")
            // prepend original character with backslash, see: https://datatracker.ietf.org/doc/html/rfc4514#section-2.4
            .Replace("\"", "\\\"")
            .Replace("#", @"\#")
            .Replace("+", @"\+")
            .Replace(",", @"\,")
            .Replace(";", @"\;")
            .Replace("<", @"\<")
            .Replace("=", @"\=")
            .Replace(">", @"\>");
    }

    #region Name sanitization
    public static String GetWcceSanitizedName(String fullName) {
        const Int32 maxLength = 51;
        StringBuilder sanitizedBuilder = fullName.Aggregate(new StringBuilder(),
            (SB, c) => isAllowedCharacter(c)
                ? SB.Append(c)
                : SB.Append('!').Append(((Int32)c).ToString("x4")));

        String sanitizedString = sanitizedBuilder.ToString();
        if (sanitizedString.Length <= maxLength) {
            return sanitizedString;
        }

        String testForIncompleteSequence = sanitizedString.Substring(maxLength - 4, 4);
        Int32 i = testForIncompleteSequence.IndexOf('!');
        Int32 splitPosition = i < 0
            ? maxLength
            : maxLength - 4 + i;
        String exceeded = sanitizedString.Substring(splitPosition);
        String truncated = sanitizedString.Remove(splitPosition);
        return truncated + "-" + getExceedHash(exceeded);
    }

    static Boolean isAllowedCharacter(Char c) {
        return c >= 0x20 && c <= 0x79 && !disallowed.Contains(c);
    }
    static String getExceedHash(IEnumerable<Char> str) {
        unchecked {
            UInt16 hash = str.Aggregate((UInt16)0, (h, c) => {
                UInt16 lowBit = (h & 0x8000) == 0 ? (UInt16)0 : (UInt16)1;
                return (UInt16)(((h << 1) | lowBit) + c);
            });
            return hash.ToString("d5");
        }
    }
    #endregion
}