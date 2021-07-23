using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Text;

namespace PKI.Utils {
    static class DsUtils {
        public const String PropConfigNameContext		= "ConfigurationNamingContext";
        public const String PropSiteObject				= "siteObject";
        public const String PropPkiEnrollmentServers	= "msPKI-Enrollment-Servers";
        public const String PropCN						= "cn";
        public const String PropDN						= "distinguishedName";
        public const String PropDisplayName				= "displayName";
        public const String PropFlags					= "flags";
        public const String PropCpsOid					= "msPKI-OID-CPS";
        public const String PropCertTemplateOid			= "msPKI-Cert-Template-OID";
        public const String PropLocalizedOid			= "msPKI-OIDLocalizedName";
        public const String PropPkiTemplateMajorVersion	= "Revision";
        public const String PropPkiTemplateMinorVersion	= "msPKI-Template-Minor-Revision";
        public const String PropPkiSchemaVersion		= "msPKI-Template-Schema-Version";
        public const String PropWhenChanged				= "WhenChanged";
        public const String PropPkiSubjectFlags			= "msPKI-Certificate-Name-Flag";
        public const String PropPkiEnrollFlags			= "msPKI-Enrollment-Flag";
        public const String PropPkiPKeyFlags			= "msPKI-Private-Key-Flag";
        public const String PropPkiNotAfter				= "pKIExpirationPeriod";
        public const String PropPkiRenewalPeriod		= "pKIOverlapPeriod";
        public const String PropPkiPathLength			= "pKIMaxIssuingDepth";
        public const String PropCertTemplateEKU			= "pKIExtendedKeyUsage";
        public const String PropPkiCertPolicy			= "msPKI-Certificate-Policy";
        public const String PropPkiCriticalExt			= "pKICriticalExtensions";
        public const String PropPkiSupersede			= "msPKI-Supersede-Templates";
        public const String PropPkiKeyCsp				= "pKIDefaultCSPs";
        public const String PropPkiKeySize				= "msPKI-Minimal-Key-Size";
        public const String PropPkiKeySpec				= "pKIDefaultKeySpec";
        public const String PropPkiKeySddl				= "msPKI-Key-Security-Descriptor";
        public const String PropPkiRaAppPolicy			= "msPKI-RA-Application-Policies";
        public const String PropPkiRaCertPolicy			= "msPKI-RA-Policies";
        public const String PropPkiRaSignature			= "msPKI-RA-Signature";
        public const String PropPkiAsymAlgo				= "msPKI-Asymmetric-Algorithm";
        public const String PropPkiSymAlgo				= "msPKI-Symmetric-Algorithm";
        public const String PropPkiSymLength			= "msPKI-Symmetric-Key-Length";
        public const String PropPkiHashAlgo				= "msPKI-Hash-Algorithm";
        public const String PropPkiKeyUsage				= "pKIKeyUsage";
        public const String PropPkiKeyUsageCng			= "msPKI-Key-Usage";

        public const String SchemaObjectIdentifier	= "msPKI-Enterprise-Oid";


        const String disallowed = @"!""#%&'()*+,/:;<=>?[\]^`{|}";
        public static String ConfigContext {
            get {
                if (Ping()) {
                    using (DirectoryEntry entry = new DirectoryEntry("LDAP://RootDSE")) {
                        return (String)entry.Properties[PropConfigNameContext].Value;
                    }
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
            using (DirectoryEntry entry = new DirectoryEntry($"LDAP://{ldapPath}")) {
                return entry.Properties.Contains(prop)
                    ? entry.Properties[prop].Value
                    : null;
            }
        }
        public static IDictionary<String, Object> GetEntryProperties(String ldapPath, params String[] properties) {
            var retValue = new Dictionary<String, Object>();
            using (DirectoryEntry entry = new DirectoryEntry($"LDAP://{ldapPath}")) {
                foreach (String prop in properties) {
                    retValue.Add(prop, entry.Properties.Contains(prop)
                        ? entry.Properties[prop].Value
                        : null);
                }
            }
            return retValue;
        }
        public static String AddEntry(String ldapPath, String name, String schemaClass) {
            using (DirectoryEntry entry = new DirectoryEntry($"LDAP://{ldapPath}")) {
                using (DirectoryEntry newEntry = entry.Children.Add(name, schemaClass)) {
                    newEntry.CommitChanges();
                    return (String) newEntry.Properties[PropDN].Value;
                }
            }
        }
        public static void RemoveEntry(String ldapPath) {
            using (var entryToDelete = new DirectoryEntry($"LDAP://{ldapPath}")) {
                using (DirectoryEntry parent = entryToDelete.Parent) {
                    parent.Children.Remove(entryToDelete);
                    parent.CommitChanges();
                }
            }
            
        }
        public static void SetEntryProperty(String ldapPath, String prop, Object value) {
            using (DirectoryEntry entry = new DirectoryEntry($"LDAP://{ldapPath}")) {
                entry.Properties[prop].Value = value;
                entry.CommitChanges();
            }
        }
        public static String Find(String ldapPath, String propName, String propValue) {
            using (var entry = new DirectoryEntry($"LDAP://{ldapPath}")) {
                using (var searcher = new DirectorySearcher(entry)) {
                    searcher.Filter = $"{propName}={propValue}";
                    return (String)searcher.FindOne()?.GetDirectoryEntry().Properties[PropDN].Value;
                }
            }
        }
        public static Boolean Ping() {
            try {
                String domain = Domain.GetComputerDomain().Name;
                return !String.IsNullOrEmpty(domain);
            } catch { return false; }
        }
        public static DirectoryEntries GetChildItems(String ldap) {
            using (DirectoryEntry entry = new DirectoryEntry($"LDAP://{ldap}")) {
                return entry.Children;
            }
        }
        public static String BindServerToSite(String computerName) {
            if (String.IsNullOrEmpty(computerName)) { return null; }
            Hashtable siteTable = new Hashtable();
            IPHostEntry ip = Dns.GetHostEntry(computerName);

            try {
                DirectoryEntry subnets = new DirectoryEntry($"LDAP://CN=Subnets,CN=Sites,{ConfigContext}");
                foreach (DirectoryEntry subnet in subnets.Children) {
                    DirectoryEntry site = new DirectoryEntry("LDAP://" + subnet.Properties[PropSiteObject].Value);
                    siteTable.Add(subnet.Properties[PropCN].Value, site.Properties[PropCN].Value);
                }
            } catch {
                return null;
            }
            foreach (String Key in siteTable.Keys) {
                String[] tokens = Key.Split('/');
                if (ip.AddressList.Any(address => Networking.InSameSubnet(tokens[0], Convert.ToInt32(tokens[1]), address.ToString()))) {
                    String S = (String) siteTable[Key];
                    return S;
                }
            }
            return null;
        }

        #region Name sanitization
        public static String GetSanitizedName(String fullName) {
            const Int32 maxLength = 51;
            StringBuilder sanitizedBuilder = fullName.Aggregate(new StringBuilder(),
                                                 (SB, c) => isAllowedCharacter(c)
                                                     ? SB.Append(c)
                                                     : SB.Append('!').Append(((Int32)c).ToString("x4")));

            String sanitizedString = sanitizedBuilder.ToString();
            if (sanitizedString.Length <= maxLength) return sanitizedString;

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
}

