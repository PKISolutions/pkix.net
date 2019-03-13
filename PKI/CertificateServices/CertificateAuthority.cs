using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using CERTADMINLib;
using CERTCLILib;
using PKI.CertificateServices.DB;
using PKI.Exceptions;
using PKI.Security;
using PKI.Security.AccessControl;
using PKI.Structs;
using PKI.Utils;
using SysadminsLV.PKI.Management.CertificateServices.Database;
using SysadminsLV.PKI.Win32;

namespace PKI.CertificateServices {
    /// <summary>
    /// The class represents Certification Authority (<strong>CA</strong>) object and contains related properties and methods.
    /// </summary>
    public class CertificateAuthority {
        readonly CCertAdmin _certAdmin = new CCertAdmin();
        readonly CCertConfig _certConfig = new CCertConfig();
        Boolean foundInDs;
        Boolean[] keyMap;

        /// <param name="computerName">Specifies the fully qualified domain name (FQDN) of the computer where Certificate Services
        /// are installed.</param>
        /// <exception cref="ArgumentNullException">Te <strong>computerName</strong> parameter is null or empty.</exception>
        /// <exception cref="ServerUnavailableException">The computer specified in the <strong>computerName</strong>
        /// parameter could not be contacted via remote registry.</exception>
        public CertificateAuthority(String computerName) {
            if (String.IsNullOrEmpty(computerName)) { throw new ArgumentNullException(nameof(computerName)); }
            RegistryOnline = CryptoRegistry.Ping(computerName);
            IsAccessible = Ping(computerName);
            lookInDs(computerName);
            if (foundInDs) {
                buildFromCertConfigOnly();
                initializeFromConfigString(ComputerName, Name);
            } else {
                if (RegistryOnline) {
                    initializeFromServerName(computerName);
                } else {
                    ServerUnavailableException e = new ServerUnavailableException(computerName);
                    e.Data.Add(nameof(e.Source), OfflineSource.Registry);
                    throw e;
                }
            }
        }
        /// <param name="computerName">
        /// Specifies the computer name where Certificate Services are installed.
        /// </param>
        /// <param name="name">
        /// Specifies the common name of the Certification Authority that is installed on the
        /// computer specified in the <strong>computerName</strong> parameter.
        /// </param>
        /// <exception cref="ArgumentNullException">Either <strong>computerName</strong> or <strong>name</strong> parameter is null or empty.</exception>
        /// <exception cref="ServerUnavailableException">The server could not be contacted via both methods: remote registry
        /// and RPC/DCOM transport.</exception>
        /// <remarks>
        /// This constructor allows to connect to a CA server if it can be contacted at least via RPC/DCOM.
        /// <para>The default behavior is to retrieve registry information via remote registry functions. If the connection is
        /// unsuccessfull, the code falls back to RPC/DCOM connections (by using <strong>ICertAdmin2</strong> COM interface) to
        /// get registry data.</para>
        /// </remarks>
        public CertificateAuthority(String computerName, String name) {
            if (String.IsNullOrEmpty(computerName)) { throw new ArgumentNullException(nameof(computerName)); }
            if (String.IsNullOrEmpty(name)) { throw new ArgumentNullException(nameof(name)); }
            RegistryOnline = CryptoRegistry.Ping(computerName);
            IsAccessible = Ping(computerName);
            lookInDs(computerName);
            initializeFromConfigString(computerName, name);
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
        /// Gets the configuration string of the Certification Authority in a form: ComputerName\SanitizedName.
        /// </summary>
        public String ConfigString { get; private set; }
        /// <summary>
        /// Gets the LDAP path of the Certification Authority in Active Directory. This property is set to <strong>Null</strong>
        /// for Standalone CAs.
        /// </summary>
        public String DistinguishedName { get; private set; }
        /// <summary>
        /// Gets the type of the Certification Authority. The value can be one of the following types:
        /// <list type="bullet">
        /// <item><strong>Enterprise Root</strong></item>
        /// <item><strong>Enterprise Subordinate</strong></item>
        /// <item><strong>Standalone Root</strong></item>
        /// <item><strong>Standalone Subordinate</strong></item>
        /// <item><strong>Undefined</strong> (if CA type cannot be recognized).</item>
        /// <item><strong>Unknown</strong> (if CA server is offline)</item>
        /// </list> 
        /// </summary>
        public String Type { get; private set; }
        /// <summary>
        /// Gets operating system of the server which runs Certification Authority role.
        /// </summary>
        public String OperatingSystem { get; private set; }
        /// <summary>
        /// Gets accessibility status for Certification Authority. Returns <strong>True</strong> if Certification Authority is online and management
        /// interfaces are accessbile, otherwise <strong>False</strong>.
        /// <para>This property does not indicate whether remote registry is available or not. Refer to <see cref="RegistryOnline"/>
        /// property to determine remote registry availability.</para>
        /// </summary>
        public Boolean IsAccessible { get; }
        /// <summary>
        /// Gets remote registry accessibility status for Certification Authority. Returns <strong>True</strong> if Certification Authority
        /// if remote registry is accessible, otherwise <strong>False</strong>.
        /// <para>This property does not indicate whether management interfaces are available or not. Refer to <see cref="IsAccessible"/>
        /// property to determine management interface availability.</para>
        /// </summary>
        public Boolean RegistryOnline { get; }
        /// <summary>
        /// Gets the status of the <strong>CertSvc</strong> service.
        /// </summary>
        public String ServiceStatus { get; private set; }
        /// <summary>
        /// Gets the status of the current CA installation.
        /// <para>This property is set to <strong>Unknown</strong> if <see cref="RegistryOnline"/> property is <strong>False</strong>.</para>
        /// </summary>
        public SetupStatusEnum SetupStatus { get; private set; }
        /// <summary>
        /// Gets the most recent CA certificate.
        /// </summary>
        public X509Certificate2 Certificate { get; private set; }
        /// <summary>
        /// Gets the most recent Base CRL object.
        /// </summary>
        public X509CRL2 BaseCRL { get; private set; }
        /// <summary>
        /// Gets the most recent Delta CRL. If CA server is not configured to use Delta CRLs, the property is empty.
        /// </summary>
        public X509CRL2 DeltaCRL { get; private set; }
        /// <summary>
        /// Gets or sets an array of Certification Authority's web services URI.
        /// </summary>
        public CESUri[] EnrollmentServiceURI { get; set; }
        internal String Version { get; private set; }
        internal String Sku { get; private set; }
        internal Boolean IsEnterprise { get; private set; }
        String Active { get; set; }

        void lookInDs(String computerName) {
            if (!DsUtils.Ping()) { return; }
            if (!computerName.Contains(".")) { computerName = computerName + "." + DsUtils.GetCurrentDomainName(); }
            _certConfig.Reset(0); //TODO
            while (_certConfig.Next() >= 0) {
                Int32 flags = Convert.ToInt32(_certConfig.GetField(CertConfigConstants.FieldFlags));
                Boolean serverNameMatch = String.Equals(_certConfig.GetField(CertConfigConstants.FieldServer), computerName, StringComparison.InvariantCultureIgnoreCase);
                if (serverNameMatch && (flags & 1) > 0) {
                    foundInDs = true;
                    return;
                }
            }
        }
        void initializeFromServerName(String computerName) {
            getConfig(computerName);
            initialize();
        }
        void initializeFromConfigString(String computerName, String name) {
            String tempConfig = computerName + "\\" + name;
            if (!RegistryOnline && !IsAccessible) {
                if (foundInDs) {
                    buildFromCertConfigOnly();
                } else {
                    ServerUnavailableException e = new ServerUnavailableException(computerName);
                    e.Data.Add(nameof(e.Source), (OfflineSource)3);
                    throw e;
                }
            } else {
                getConfig(computerName, tempConfig);
                initialize();
            }
        }
        void initialize() {
            getType();
            getVersion();
            getWmiData();
            getCaProperty();
            buildKeyMap();
            getCertSvcServiceStatus();
            getInfoFromDs();
            releaseCom();
        }
        void getConfig(String computerName, String configString = "") {
            if (RegistryOnline) {
                Active = (String)CryptoRegistry.GetRReg("Active", "", computerName);
                ComputerName = (String)CryptoRegistry.GetRReg("CAServerName", Active, computerName);
                Name = (String)CryptoRegistry.GetRReg("CommonName", Active, computerName);
            } else {
                if (!String.IsNullOrEmpty(configString) && IsAccessible) {
                    ComputerName = (String)CryptoRegistry.GetRegFallback(configString, String.Empty, "CAServerName");
                    Name = (String)CryptoRegistry.GetRegFallback(configString, String.Empty, "CommonName");
                } else {
                    ServerUnavailableException e = new ServerUnavailableException(computerName);
                    e.Data.Add(nameof(e.Source), (OfflineSource)3);
                    throw e;
                }
            }
            ConfigString = ComputerName + "\\" + Name;
        }
        void getType() {
            Int32 type;
            if (RegistryOnline) {
                type = (Int32)CryptoRegistry.GetRReg("CAType", Active, ComputerName);
            } else {
                type = (Int32)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CAType");
            }
            switch (type) {
                case 0: Type = "Enterprise Root CA"; IsEnterprise = true; break;
                case 1: Type = "Enterprise Subordinate CA"; IsEnterprise = true; break;
                case 3: Type = "Standalone Root CA"; break;
                case 4: Type = "Standalone Subordinate CA"; break;
                default: Type = "Undefined"; break;
            }
        }
        void getVersion() {
            if (RegistryOnline) {
                switch ((Int32)CryptoRegistry.GetRReg("Version", String.Empty, ComputerName)) {
                    case 0x00010001: Version = "2000"; break;
                    case 0x00020002: Version = "2003"; break;
                    case 0x00030001: Version = "2008"; break;
                    case 0x00040001: Version = "2008R2"; break;
                    case 0x00050001: Version = "2012"; break;
                    case 0x00060001: Version = "2012R2"; break;
                    case 0x00070001: Version = "2016"; break;
                }
                SetupStatus = (SetupStatusEnum)CryptoRegistry.GetRReg("SetupStatus", String.Empty, ComputerName);
            } else {
                String ver = (String)_certAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropProductversion, 0, 4, 0);
                String[] vers = ver.Split(new [] { ":" }, StringSplitOptions.RemoveEmptyEntries);
                switch (vers[0]) {
                    case "5.0": Version = "2000"; break;
                    case "5.2": Version = "2003"; break;
                    case "6.0": Version = "2008"; break;
                    case "6.1": Version = "2008R2"; break;
                    case "6.2": Version = "2012"; break;
                    case "6.3": Version = "2012R2"; break;
                    default:
                        Version = vers[0].StartsWith("10.0")
                            ? "2016"
                            : "Unknown";
                        break;
                }
                SetupStatus = SetupStatusEnum.Unknown;
            }
        }
        void getWmiData() {
            try {
                foreach (ManagementObject obj in WMI.GetWmi("Select Caption, OSProductSuite from Win32_OperatingSystem", ComputerName)) {
                    OperatingSystem = (String)obj["Caption"];
                    UInt32 osSuite = (UInt32)obj["OSProductSuite"];
                    if ((osSuite & 2) > 0) { Sku = "Enterprise"; }
                    if ((osSuite & 128) > 0) { Sku = "Datacenter"; }
                }
            } catch { }
        }
        void getCaProperty() {
            if (!IsAccessible) { return; }
            Int32 count = (Int32)_certAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropCasigcertcount, 0, 1, 0);
            Certificate = new X509Certificate2(
                Convert.FromBase64String(
                    (String)_certAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropCasigcert, count - 1, 3, 1)
                    )
                );
            // loop over cert index from higher index to lower. Get first entry where CRL appears
            for (Int32 index = count - 1; index >= 0; index--) {
                try {
                    String crl = (String)_certAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropBasecrl, index, 3, 1);
                    if (crl != String.Empty) {
                        BaseCRL = new X509CRL2(Convert.FromBase64String(crl));
                        try {
                            String crl2 = (String)_certAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropDeltacrl, index, 3, 1);
                            if (crl2 != String.Empty) { DeltaCRL = new X509CRL2(Convert.FromBase64String(crl2)); }
                        } catch { }
                        break;
                    }
                } catch { }
            }
        }
        void getCertSvcServiceStatus() {
            if (RegistryOnline || IsAccessible) {
                try {
                    ServiceController sc = new ServiceController("CertSvc", ComputerName);
                    ServiceStatus = sc.Status.ToString();
                } catch { ServiceStatus = "Unknown"; }
            } else {
                ServiceStatus = "Unknown";
            }
        }
        void getInfoFromDs() {
            if (IsEnterprise && DsUtils.Ping()) {
                string domain = (string) DsUtils.GetEntryProperty(String.Join(".", this.ComputerName.Split('.').Where((v, i) => i != 0)) + "/RootDSE", "rootDomainNamingContext");
                String dn = "CN=" + this.Name +
                    ",CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + domain;
                DistinguishedName = dn;
                DisplayName = (String)DsUtils.GetEntryProperty(dn, "DisplayName");
                try {
                    String wes  = (String)DsUtils.GetEntryProperty(dn, "msPKI-Enrollment-Servers");
                    if (!String.IsNullOrEmpty(wes)) {
                        getCesUri(wes);
                    }
                } catch { }
                
            }
            if (String.IsNullOrEmpty(DisplayName)) { DisplayName = Name; }
        }
        void getCesUri(String ldapuri) {
            EnrollmentServiceURI = ldapuri
                .Split(new[] {"\n\n"}, StringSplitOptions.None)
                .Select(str => new CESUri(str, DisplayName))
                .ToArray();
        }
        void buildFromCertConfigOnly() {
            IsEnterprise = true;
            Name = _certConfig.GetField(CertConfigConstants.FieldSanitizedName);
            DisplayName = _certConfig.GetField(CertConfigConstants.FieldCommonName);
            ComputerName = _certConfig.GetField(CertConfigConstants.FieldServer);
            ConfigString = _certConfig.GetField(CertConfigConstants.FieldConfig);
            getInfoFromDs();
        }
        void releaseCom() {
            CryptographyUtils.ReleaseCom(_certAdmin, _certConfig);
        }
        void buildKeyMap() {
            if (!IsAccessible) { return; }
            Int32 count = (Int32)_certAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropCasigcertcount, 0, 1, 0);
            keyMap = new Boolean[count];
            for (Int32 index = count - 1; index >= 0; index--) {
                try {
                    _certAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropBasecrl, index, CertAdmConstants.ProptypeBinary, 0);
                    keyMap[index] = true;
                } catch {
                    keyMap[index] = false;
                }
            }
        }

        internal Boolean[] GetKeyMap() {
            return keyMap;
        }
        internal String GetConfigEntry(String entry) {
            switch (entry) {
                case "CAServerName": return ComputerName;
                case "ServerShortName": return ComputerName.Split('.')[0];
                case "CommonName": return Name;
                case "CATruncatedName": return DsUtils.GetSanitizedName(Name);
                case "ConfigurationContainer": return (String)CryptoRegistry.GetRReg("DSConfigDN", Name, ComputerName);
                default: return String.Empty;
            }
        }

        /// <summary>
        /// Attempts to check Certification Authority's management interfaces availability.
        /// </summary>
        /// <exception cref="UninitializedObjectException">The <see cref="CertificateAuthority"/> object is not
        /// initialized through a class constructor.</exception>
        /// <returns><strong>True</strong> if management interfaces are available and accessible, otherwise <strong>False</strong>.</returns>
        /// <remarks>
        /// The caller must have at least <strong>Read</strong> permissions on the CA server to ping management interfaces.
        /// Otherwise the method always returns <strong>False</strong>, regardles of actual interface state.
        /// </remarks>
        public Boolean Ping() {
            if (String.IsNullOrEmpty(ComputerName)) {throw new UninitializedObjectException();}
            Boolean online = false;
            CertAdm.CertSrvIsServerOnline(ComputerName, ref online);
            return online;
        }
        /// <summary>
        /// Gets Certification Authority database schema for specified table.
        /// </summary>
        /// <param name="table">Database table to process.</param>
        /// <exception cref="UninitializedObjectException">
        /// Current object is not initialized.
        /// </exception>
        /// <exception cref="ServerUnavailableException">
        /// Current CA server could not be contacted via remote registry and RPC protocol.
        /// </exception>
        /// <returns>Database schema (column name, data type, cell capacity).</returns>
        [Obsolete("Use 'AdcsDbReader.GetTableSchema()' method instead.", true)]
        public Schema[] GetSchema(TableList table = TableList.Request) {
            if (String.IsNullOrEmpty(Name)) { throw new UninitializedObjectException(); }
            if (!Ping()) {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
                throw e;
            }
            CCertView CaView = new CCertView();
            try {
                List<Schema> items = new List<Schema>();
                CaView.OpenConnection(ConfigString);
                CaView.SetTable((Int32)table);
                IEnumCERTVIEWCOLUMN columns = CaView.EnumCertViewColumn(0);
                while (columns.Next() != -1) {
                    String name = columns.GetName();
                    String displayname = columns.GetDisplayName();
                    DataTypeEnum dataType = (DataTypeEnum)columns.GetType();
                    Int32 maxLength = columns.GetMaxLength();
                    Boolean isIndexed = Convert.ToBoolean(columns.IsIndexed());
                    items.Add(new Schema(name, displayname, dataType, maxLength, isIndexed));
                }
                columns.Reset();
                CryptographyUtils.ReleaseCom(columns);
                return items.ToArray();
            } catch (Exception e) {
                throw Error.ComExceptionHandler(e);
            } finally {
                CryptographyUtils.ReleaseCom(CaView);
            }
        }
        /// <summary>
        /// Returns an instance of ADCS database reader.
        /// </summary>
        /// <param name="table">Initial view table name. Default is 'Issued' view table.</param>
        /// <returns>
        /// An instance of ADCS database reader.
        /// </returns>
        public AdcsDbReader GetDbReader(AdcsDbViewTableName table = AdcsDbViewTableName.Issued) {
            return new AdcsDbReader(this, table);
        }
        /// <summary>
        /// Returns all CA certificates.
        /// </summary>
        /// <exception cref="UninitializedObjectException">
        /// Current object is not initialized.
        /// </exception>
        /// <exception cref="ServerUnavailableException">
        /// Current CA server could not be contacted via remote registry and RPC protocol.
        /// </exception>
        /// <returns>A collection of CA certificates.</returns>
        public X509Certificate2Collection GetCACerts() {
            if (String.IsNullOrEmpty(Name)) { throw new UninitializedObjectException(); }
            if (!Ping()) {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
                throw e;
            }
            var CertAdmin = new CCertAdmin();
            X509Certificate2Collection certs = new X509Certificate2Collection();
            Int32 count = (Int32)CertAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropCasigcertcount, 0, 1, 0);
            for (Int32 index = 0; index < count; index++) {
                certs.Add(new X509Certificate(Convert.FromBase64String((String)CertAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropCasigcert, index, 3, 1))));
            }
            CryptographyUtils.ReleaseCom(CertAdmin);
            return certs;
        }
        /// <summary>
        /// Retrieves the most recent 'CA Exchange' certificate. If the certificate does not exist, the method
        /// will instruct CA server to generate or enroll a new one.
        /// </summary>
        /// <exception cref="UninitializedObjectException">The object is not properly initialized.</exception>
        /// <exception cref="ServerUnavailableException">CA server is not accessible via RPC/DCOM.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller do not have at least <strong>Read</strong> permissions.</exception>
        /// <exception cref="PlatformNotSupportedException">Current CA is not <strong>Enterprise CA</strong>. Only Enterprise CAs supports this feature.</exception>
        /// <returns>CA Exchange certificate.</returns>
        public X509Certificate2 GetCAExchangeCertificate() {
            if (String.IsNullOrEmpty(Name)) { throw new UninitializedObjectException(); }
            if (!IsEnterprise) { throw new PlatformNotSupportedException(Error.E_NONENTERPRISE); }
            if (!Ping()) {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
                throw e;
            }
            var CertAdmin = new CCertAdmin();
            try {
                Int32 index = (Int32)CertAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropCaxchgcertcount, 0, 1, 0) - 1;
                if (index >= 0) {
                    String Base64 = (String)CertAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropCaxchgcert, index, 3, 1);
                    return new X509Certificate2(Convert.FromBase64String(Base64));
                }
                throw new Exception(String.Format(Error.E_XCHGUNAVAILABLE, DisplayName));
            } catch (Exception e) {
                throw Error.ComExceptionHandler(e);
            } finally {
                CryptographyUtils.ReleaseCom(CertAdmin);
            }
        }
        /// <summary>
        /// Stops Certification Authority service.
        /// </summary>
        /// <exception cref="InvalidOperationException">The service is already stopped.</exception>
        public void Stop() {
            ServiceController sc = new ServiceController("CertSvc", ComputerName);
            if (sc.Status == ServiceControllerStatus.Running) {
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped);
                sc.Close();
            } else { throw new InvalidOperationException(); }
        }
        /// <summary>
        /// Starts Certification Authority service.
        /// </summary>
        /// <exception cref="InvalidOperationException">The service is already running or pending.</exception>
        public void Start() {
            ServiceController sc = new ServiceController("CertSvc", ComputerName);
            if (sc.Status == ServiceControllerStatus.Stopped) {
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running);
                sc.Close();
            } else { throw new InvalidOperationException(); }
        }
        /// <summary>
        /// Restarts a current Certification Authority instance. This method restarts 'certsvc' service.
        /// </summary>
        public void Restart() {
            ServiceController sc = new ServiceController("CertSvc", ComputerName);
            try {
                if (sc.Status == ServiceControllerStatus.Running) {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped);
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running);
                } else {
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running);
                }
            } finally { sc.Close(); }
        }
        /// <summary>
        /// Returns all roles granted on the CA to the caller.
        /// </summary>
        /// <exception cref="UninitializedObjectException">The object is not properly initialized.</exception>
        /// <exception cref="ServerUnavailableException">CA server is not accessible via RPC/DCOM.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller do not have at least <strong>Read</strong> permissions.</exception>
        /// <returns>Granted roles.</returns>
        public CARoleEnum GetMyRoles() {
            if (String.IsNullOrEmpty(ConfigString)) {throw new UninitializedObjectException();}
            if (!IsAccessible) {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
                throw e;
            }
            var CertAdmin = new CCertAdmin();
            return (CARoleEnum)CertAdmin.GetMyRoles(ConfigString);
        }
        ///  <summary>
        ///  This method publishes certificate revocation lists (CRLs) for a certification authority (CA).
        ///  <para>
        ///  The PublishCRL method publishes a CRL based on the CA's current certificate, as well as CRLs
        ///  based on any CA certificates that have been renewed and are not yet expired.
        ///  </para>
        ///  </summary>
        ///  <param name="deltaOnly">
        /// 	A delta CRL is published, or the most recent delta CRL is republished if <strong>updateFilesOnly</strong>
        ///  parameter is set. Note that if the CA has not enabled delta CRL publishing, use of this flag will result
        ///  in an error.</param>
        ///  <param name="updateFilesOnly">
        ///  The most recent base or delta CRL, is republished. The CA will not republish a CRL to a CRL distribution point
        ///   if the CRL at the distribution point is already the most recent CRL.
        ///  </param>
        /// <exception cref="UninitializedObjectException">The object is not properly initialized.</exception>
        /// <exception cref="ServerUnavailableException">CA server is not accessible via RPC/DCOM.</exception>
        public void PublishCRL(Boolean deltaOnly = false, Boolean updateFilesOnly = false) {
            if (String.IsNullOrEmpty(Name)) { throw new UninitializedObjectException(); }
            if (!Ping()) {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
                throw e;
            }
            var CertAdmin = new CCertAdmin();
            try {
                if (deltaOnly) {
                    CertAdmin.PublishCRLs(ConfigString, new DateTime(0), 0x2);
                } else if (updateFilesOnly) {
                    CertAdmin.PublishCRLs(ConfigString, new DateTime(0), 0x11);
                } else {
                    CertAdmin.PublishCRLs(ConfigString, new DateTime(0), 0x1);
                }
            } catch (Exception e) {
                throw Error.ComExceptionHandler(e);
            } finally { CryptographyUtils.ReleaseCom(CertAdmin); }
        }
        /// <summary>
        /// Updates Enrollment Services URLs in the Active Directory.
        /// </summary>
        public void UpdateEnrollmentServiceUri() {
            if (String.IsNullOrEmpty(DistinguishedName)) {
                throw new NotSupportedException("Enrollment Service URLs are not supported for Standalone CAs.");
            }
            Object value = null;
            if (EnrollmentServiceURI != null && EnrollmentServiceURI.Length > 0) {
                List<String> uris = new List<String>();
                foreach (CESUri uri in EnrollmentServiceURI) {
                    uri.DisplayName = DisplayName;
                    uris.Add(uri.Priority + "\n" + (Int32) uri.Authentication + "\n" + Convert.ToInt32(uri.RenewalOnly) + "\n" +
                             uri.Uri.AbsoluteUri);
                }
                value = uris.ToArray();
            }
            DsUtils.SetEntryProperty(DistinguishedName, DsUtils.PropPkiEnrollmentServers, value);
        }
        /// <summary>
        /// Gets the access control list (<strong>ACL</strong>) for the current Certification Authority.
        /// </summary>
        /// <returns>An ACL object.</returns>
        /// <remarks>Returned object inherits from <see cref="CommonObjectSecurity"/> and implements common methods.</remarks>
        public CASecurityDescriptor GetSecurityDescriptor() {
            var sd = new CASecurityDescriptor(this);
            Byte[] sdBinary;
            if (CryptoRegistry.Ping(ComputerName)) {
                sdBinary = (Byte[])CryptoRegistry.GetRReg("Security", Name, ComputerName);
            } else {
                if (Ping(ComputerName)) {
                    sdBinary = (Byte[])CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "Security");
                } else {
                    ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                    e.Data.Add(nameof(e.Source), (OfflineSource)3);
                    throw e;
                }
            }
            sd.SetSecurityDescriptorBinaryForm(sdBinary);
            return sd;
        }

        /// <summary>
        /// Attempts to check specified Certification Authority's management interfaces availability.
        /// </summary>
        /// <param name="computerName">CA's computer host name. Can be either short (NetBIOS) or fully qualified (FQDN) name.</param>
        /// <exception cref="ArgumentNullException">If the <strong>computerName</strong> parameter is null or empty.</exception>
        /// <returns><strong>True</strong> if management interfaces are available and accessible, otherwise <strong>False</strong>.</returns>
        public static Boolean Ping(String computerName) {
            if (String.IsNullOrEmpty(computerName)) { throw new ArgumentNullException(nameof(computerName)); }
            Boolean online = false;
            CertAdm.CertSrvIsServerOnline(computerName, ref online);
            return online;
        }
        /// <summary>
        /// Stops Certification Authority service on a specified server.
        /// </summary>
        /// <param name="computerName">CA's computer host name. Can be either short (NetBIOS) or fully qualified (FQDN) name.</param>
        /// <exception cref="InvalidOperationException">The service is already stopped.</exception>
        public static void Stop(String computerName) {
            ServiceController sc = new ServiceController("CertSvc", computerName);
            if (sc.Status == ServiceControllerStatus.Running) {
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped);
                sc.Close();
            } else { throw new InvalidOperationException(); }
        }
        /// <summary>
        /// Starts Certification Authority service on a specified server.
        /// </summary>
        /// <param name="computerName">CA's computer host name. Can be either short (NetBIOS) or fully qualified (FQDN) name.</param>
        /// <exception cref="InvalidOperationException">The service is already running.</exception>
        public static void Start(String computerName) {
            ServiceController sc = new ServiceController("CertSvc", computerName);
            if (sc.Status == ServiceControllerStatus.Stopped) {
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running);
                sc.Close();
            } else { throw new InvalidOperationException(); }
        }
        /// <summary>
        /// Restarts a specified Certification Authority service. This method restarts 'certsvc' service.
        /// </summary>
        /// <param name="computerName">CA's computer host name. Can be either short (NetBIOS) or fully qualified (FQDN) name.</param>
        public static void Restart(String computerName) {
            ServiceController sc = new ServiceController("CertSvc", computerName);
            try {
                if (sc.Status == ServiceControllerStatus.Running) {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped);
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running);
                } else {
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running);
                }
            } finally { sc.Close(); }
        }
        /// <summary>
        /// Connects to a specified Certification Authority server. This method allows you to connect to either
        /// Standalone CA or Enterprise CA.
        /// </summary>
        /// <param name="computerName">Specifies the computer name to connect.</param>
        /// <returns>A CertificationAuthority object.</returns>
        /// <exception cref="ArgumentNullException">If the <strong>computerName</strong> parameter is <strong>null</strong> or <strong>empty</strong>.</exception>
        public static CertificateAuthority Connect(String computerName) {
            if (String.IsNullOrEmpty(computerName)) {throw new ArgumentNullException(nameof(computerName));}
            return new CertificateAuthority(computerName);
        }
        /// <summary>
        /// <para>This method is obsolete.</para>
        /// Enumerates registered Enterprise Certification Authorities from the current Active Directory forest.
        /// </summary>
        /// <param name="findType">Specifies CA object search type. The search type can be either: <strong>Name</strong>
        /// or <strong>Server</strong>.</param>
        /// <param name="findValue">Specifies search pattern for a type specifed in <strong>findType</strong> argument.
        /// Wildcard characters: * and ? are accepted.</param>
        /// <returns>Enterprise Certification Authority collection.</returns>
        [Obsolete("This method is obsolete. Use 'EnumEnterpriseCAs' method instead.", true)]
        public static CertificateAuthority[] GetCA(String findType, String findValue) {
            return EnumEnterpriseCAs(findType, findValue);
        }
        /// <summary>
        /// Enumerates registered Enterprise Certification Authorities from the current Active Directory forest.
        /// </summary>
        /// <param name="findType">Specifies CA object search type. The search type can be either: <strong>Name</strong>
        /// or <strong>Server</strong>.</param>
        /// <param name="findValue">Specifies search pattern for a type specifed in <strong>findType</strong> argument.
        /// Wildcard characters: * and ? are accepted.</param>
        /// <returns>Enterprise Certification Authority collection.</returns>
        public static CertificateAuthority[] EnumEnterpriseCAs(String findType, String findValue) {
            if (!DsUtils.Ping()) { throw new Exception("Non-domain environments are not supported."); }
            List<CertificateAuthority> CAs = new List<CertificateAuthority>();
            CCertConfig certConfig = new CCertConfig();

            while (certConfig.Next() >= 0) {
                Int32 flags = Convert.ToInt32(certConfig.GetField("Flags"));
                if ((flags & 1) == 0) { continue; }
                Wildcard wildcard = new Wildcard(findValue, RegexOptions.IgnoreCase);
                switch (findType.ToLower()) {
                    case "name":
                        if (!wildcard.IsMatch(certConfig.GetField("CommonName"))) { continue; }
                        break;
                    case "server":
                        if (!wildcard.IsMatch(certConfig.GetField("Server"))) { continue; }
                        break;
                    default:
                        throw new ArgumentException("The value for 'findType' must be either 'Name' or 'Server'.");
                }
                CAs.Add(new CertificateAuthority(certConfig.GetField("Server"), certConfig.GetField("SanitizedName")));
            }
            CryptographyUtils.ReleaseCom(certConfig);
            return CAs.ToArray();
        }
    }
}
