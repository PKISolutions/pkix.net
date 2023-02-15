using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using PKI.Exceptions;
using PKI.Utils;
using SysadminsLV.Asn1Parser;

namespace PKI.CertificateServices.PolicyModule {
    /// <summary>
    /// Contains extension list that are processed by policy module during certificate issuance.
    /// </summary>
    public class ExtensionList {
        String ConfigString, ActivePolicyModule;

        /// <param name="certificateAuthority">Specifies an existing <see cref="CertificateAuthority"/> object.</param>
        /// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
        public ExtensionList(CertificateAuthority certificateAuthority) {
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
        /// Gets extension collection in the request that are processed by the CA during certificate issuance. If the incoming request contains an extension
        /// that is listed in this property, they are added to issued certificate. If extension information in the request conflicts with CA settings
        /// (policy module or template settings), request extension information is silently ignored.
        /// </summary>
        public Oid[] EnabledExtensionList { get; private set; }
        /// <summary>
        /// Gets extension collection in the offline request that are processed by the CA during certificate issuance. 'Offline' requests are requests
        /// where subject information is used by the CA to construct issued certificate. If the certificate template is configured to build subject based
        /// on information retrieved from Active Directory, all extensions in the request that are listed in the property are silently igmored.
        /// If the incoming request contains an extension that is listed in this property and certificate template is configured to build subject information
        /// from incoming request, they are added to issued certificate. If extension information in the request conflicts with CA settings
        /// (policy module or template settings), request extension information is silently ignored.
        /// </summary>
        /// <remarks>For Standalone CA all incoming requests are treated as 'offline'</remarks>
        public Oid[] OfflineExtensionList { get; private set; }
        /// <summary>
        /// Gets extension list that are not included in issued certificate even if they are included in certificate request and/or defined by certificate template.
        /// </summary>
        public Oid[] DisabledExtensionList { get; private set; }
        /// <summary>
        /// Indiciates whether the object was modified after it was instantiated.
        /// </summary>
        public Boolean IsModified { get; private set; }

        void m_initialize(CertificateAuthority certificateAuthority) {
            List<Oid> Oids = new List<Oid>();
            Name = certificateAuthority.Name;
            DisplayName = certificateAuthority.DisplayName;
            ComputerName = certificateAuthority.ComputerName;
            ConfigString = certificateAuthority.ConfigString;
            if (CryptoRegistry.Ping(ComputerName)) {
                ActivePolicyModule = (String)CryptoRegistry.GetRReg("Active", $@"{Name}\PolicyModules", ComputerName);

                String[] oidstrings = (String[])CryptoRegistry.GetRReg("EnableRequestExtensionList", $@"{Name}\PolicyModules\{ActivePolicyModule}", ComputerName);
                Oids.AddRange(oidstrings.Select(item => new Oid(item)));
                EnabledExtensionList = Oids.ToArray();

                Oids.Clear();
                oidstrings = (String[])CryptoRegistry.GetRReg("EnableEnrolleeRequestExtensionList", $@"{Name}\PolicyModules\{ActivePolicyModule}", ComputerName);
                Oids.AddRange(oidstrings.Select(item => new Oid(item)));
                OfflineExtensionList = Oids.ToArray();

                Oids.Clear();
                oidstrings = (String[])CryptoRegistry.GetRReg("DisableExtensionList", $@"{Name}\PolicyModules\{ActivePolicyModule}", ComputerName);
                Oids.AddRange(oidstrings.Select(item => new Oid(item)));
                DisabledExtensionList = Oids.ToArray();
                Oids.Clear();
            } else {
                if (CertificateAuthority.Ping(ComputerName)) {
                    ActivePolicyModule = (String)CryptoRegistry.GetRReg("Active", $@"{Name}\PolicyModules", ComputerName);
                    String[] oidstrings = (String[])CryptoRegistry.GetRegFallback(ConfigString, $@"PolicyModules\{ActivePolicyModule}", "EnableRequestExtensionList");
                    Oids.AddRange(oidstrings.Select(item => new Oid(item)));
                    EnabledExtensionList = Oids.ToArray();

                    Oids.Clear();
                    oidstrings = (String[])CryptoRegistry.GetRegFallback(ConfigString, $@"PolicyModules\{ActivePolicyModule}", "EnableEnrolleeRequestExtensionList");
                    Oids.AddRange(oidstrings.Select(item => new Oid(item)));
                    OfflineExtensionList = Oids.ToArray();

                    Oids.Clear();
                    oidstrings = (String[])CryptoRegistry.GetRegFallback(ConfigString, $@"PolicyModules\{ActivePolicyModule}", "DisableExtensionList");
                    Oids.AddRange(oidstrings.Select(item => new Oid(item)));
                    DisabledExtensionList = Oids.ToArray();
                } else {
                    ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                    e.Data.Add(nameof(e.Source), (OfflineSource)3);
                    throw e;
                }
            }
        }

        /// <summary>
        /// Adds certificate extension object identifier (OID) value to a specified extension group.
        /// </summary>
        /// <param name="extensionType">Specifies the extension type. Possible values are: <strong>EnabledExtensionList</strong>, <strong>OfflineExtensionList</strong>
        /// and <strong>DisabledExtensionList</strong>.
        /// <para>If extension is added, <see cref="IsModified"/> property is set to <strong>True</strong>.</para></param>
        /// <param name="oid">Certificate extension object identifier.</param>
        /// <exception cref="ArgumentNullException">The <strong>extensionType</strong> parameter is <strong>Null</strong>.</exception>
        /// <exception cref="ArgumentException">The <strong>extensionType</strong> parameter value is not valid, or <strong>oid</strong> parameter is invalid
        /// object identifier.</exception>
        public void Add(String extensionType, Oid oid) {
            try { Asn1Utils.EncodeObjectIdentifier(oid); }
            catch { throw new ArgumentException("Specified object identifier is not valid or is not resolvable"); }
            if (String.IsNullOrEmpty(extensionType)) {
                throw new ArgumentNullException(nameof(extensionType));
            }
            List<Oid> existing;
            switch (extensionType.ToLower()) {
                case "enabledextensionlist":
                    existing = new List<Oid>(EnabledExtensionList);
                    if (!GenericArray.OidContains(EnabledExtensionList, oid)) {
                        existing.Add(oid);
                        IsModified = true;
                    }
                    EnabledExtensionList = existing.ToArray();
                    break;
                case "offlineextensionlist":
                    existing = new List<Oid>(OfflineExtensionList);
                    if (!GenericArray.OidContains(OfflineExtensionList, oid)) {
                        existing.Add(oid);
                        IsModified = true;
                    }
                    OfflineExtensionList = existing.ToArray();
                    break;
                case "disabledextensionlist":
                    existing = new List<Oid>(DisabledExtensionList);
                    if (!GenericArray.OidContains(DisabledExtensionList, oid)) {
                        existing.Add(oid);
                        IsModified = true;
                    }
                    DisabledExtensionList = existing.ToArray();
                    break;
                default:
                    throw new ArgumentException(
                        "Invalid extension type is specified. Allowed types are: EnabledExtensionList, OfflineExtensionList and DisabledExtensionList.");
            }
        }

        /// <summary>
        /// Removes certificate extension object identifier (OID) value from a specified extension group.
        /// </summary>
        /// <param name="extensionType">Specifies the extension type. Possible values are: <strong>EnabledExtensionList</strong>, <strong>OfflineExtensionList</strong>
        /// and <strong>DisabledExtensionList</strong>.
        /// <para>If extension is removed, <see cref="IsModified"/> property is set to <strong>True</strong>.</para></param>
        /// <param name="oid">Certificate extension object identifier.</param>
        /// <exception cref="ArgumentNullException">The <strong>extensionType</strong> parameter is <strong>Null</strong>.</exception>
        /// <exception cref="ArgumentException">The <strong>extensionType</strong> parameter value is incorrect, or <strong>oid</strong> parameter is invalid
        /// object identifier.</exception>
        public void Remove(String extensionType, Oid oid) {
            if (String.IsNullOrEmpty(Name)) { throw new UninitializedObjectException(); }
            try { Asn1Utils.EncodeObjectIdentifier(oid); }
            catch { throw new ArgumentException("Specified object identifier is not valid or is not resolvable"); }
            if (String.IsNullOrEmpty(extensionType)) {
                throw new ArgumentNullException(nameof(extensionType));
            }
            List<Oid> existing;
            switch (extensionType.ToLower()) {
                case "enabledextensionlist":
                    existing = new List<Oid>(EnabledExtensionList);
                    if (GenericArray.OidContains(EnabledExtensionList, oid)) {
                        GenericArray.RemoveOid(existing, oid);
                        IsModified = true;
                    }
                    EnabledExtensionList = existing.ToArray();
                    break;
                case "offlineextensionlist":
                    existing = new List<Oid>(OfflineExtensionList);
                    if (GenericArray.OidContains(EnabledExtensionList, oid)) {
                        GenericArray.RemoveOid(existing, oid);
                        IsModified = true;
                    }
                    OfflineExtensionList = existing.ToArray();
                    break;
                case "disabledextensionlist":
                    existing = new List<Oid>(DisabledExtensionList);
                    if (GenericArray.OidContains(DisabledExtensionList, oid)) {
                        GenericArray.RemoveOid(existing, oid);
                        IsModified = true;
                    }
                    DisabledExtensionList = existing.ToArray();
                    break;
                default:
                    throw new ArgumentException(
                        "Invalid extension type is specified. Allowed types are: EnabledExtensionList, OfflineExtensionList and DisabledExtensionList.");
            }
        }
        /// <summary>
        /// Updates policy module extension lists by writing them to Certification Authority.
        /// </summary>
        /// <param name="restart">
        /// Indiciates whether to restart certificate services to immediately apply changes. Updated settings has no effect
        /// until CA service is restarted.</param>
        /// <exception cref="UnauthorizedAccessException">
        /// If the caller do not have sufficient permissions to make changes in the CA configuration.
        /// </exception>
        /// <exception cref="ServerUnavailableException">
        /// If the target CA server could not be contacted via remote registry and RPC protocol.
        /// </exception>
        /// <returns>
        /// <strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
        /// and the method returns <strong>False</strong>.
        /// </returns>
        /// <remarks>The caller must have <strong>Administrator</strong> permissions on the target CA server.</remarks>
        public Boolean SetInfo(Boolean restart) {
            if (IsModified) {
                List<String> oidstrings;
                if (CryptoRegistry.Ping(ComputerName)) {
                    String path = $@"{Name}\PolicyModules\{ActivePolicyModule}";

                    oidstrings = EnabledExtensionList.Select(oid => oid.Value).ToList();
                    CryptoRegistry.SetRReg(oidstrings, "EnableRequestExtensionList", path, ComputerName);
                    
                    oidstrings.Clear();
                    oidstrings.AddRange(OfflineExtensionList.Select(oid => oid.Value));
                    CryptoRegistry.SetRReg(oidstrings, "EnableEnrolleeRequestExtensionList", path, ComputerName);

                    oidstrings.Clear();
                    oidstrings.AddRange(DisabledExtensionList.Select(oid => oid.Value));
                    CryptoRegistry.SetRReg(oidstrings, "DisableExtensionList", path, ComputerName);
                    oidstrings.Clear();

                    if (restart) { CertificateAuthority.Restart(ComputerName); }
                    IsModified = false;
                    return true;
                }
                if (CertificateAuthority.Ping(ComputerName)) {
                    String path = $@"PolicyModules\{ActivePolicyModule}";

                    oidstrings = EnabledExtensionList.Select(oid => oid.Value).ToList();
                    CryptoRegistry.SetRegFallback(ConfigString, path, "EnableRequestExtensionList", oidstrings.ToArray());

                    oidstrings.Clear();
                    oidstrings.AddRange(OfflineExtensionList.Select(oid => oid.Value));
                    CryptoRegistry.SetRegFallback(ConfigString, path, "EnableEnrolleeRequestExtensionList", oidstrings.ToArray());

                    oidstrings.Clear();
                    oidstrings.AddRange(DisabledExtensionList.Select(oid => oid.Value));
                    CryptoRegistry.SetRegFallback(ConfigString, path, "DisableExtensionList", oidstrings.ToArray());
                    oidstrings.Clear();

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
        /// <summary>
        /// Displays extension lists in text format.
        /// </summary>
        /// <returns>Extension lists.</returns>
        public override String ToString() {
            String nl = Environment.NewLine;
            StringBuilder SB = new StringBuilder();
            SB.Append($"Extension list for '{DisplayName}' CA server:{nl}");
            SB.Append($"[Enabled Extensions]{Environment.NewLine}");
            if (EnabledExtensionList.Length > 0) {
                foreach (Oid oid in EnabledExtensionList) {
                    SB.Append($"    {oid.Value}");
                    if (oid.FriendlyName != String.Empty) {
                        SB.Append($" ({oid.FriendlyName}){nl}");
                    }
                }
            } else {
                SB.Append($"    No extensions.{nl}");
            }
            SB.Append($"[Offline Extensions]{nl}");
            if (OfflineExtensionList.Length > 0) {
                foreach (Oid oid in OfflineExtensionList) {
                    SB.Append($"    {oid.Value}");
                    if (oid.FriendlyName != String.Empty) {
                        SB.Append($" ({oid.FriendlyName}){nl}");
                    }
                }
            } else {
                SB.Append($"    No extensions.{nl}");
            }
            SB.Append($"[Disabled Extensions]{nl}");
            if (DisabledExtensionList.Length > 0) {
                foreach (Oid oid in DisabledExtensionList) {
                    SB.Append($"    {oid.Value}");
                    if (oid.FriendlyName != String.Empty) {
                        SB.Append($" ({oid.FriendlyName}){nl}");
                    }
                }
            } else {
                SB.Append($"    No extensions.{nl}");
            }
            SB.Append(nl);
            return SB.ToString();
        }
    }
}