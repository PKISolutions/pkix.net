using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using CERTADMINLib;
using PKI.Exceptions;
using PKI.Utils;
using SysadminsLV.PKI.Dcom;
using SysadminsLV.PKI.Dcom.Implementations;
using SysadminsLV.PKI.Management.ActiveDirectory;
using SysadminsLV.PKI.Management.CertificateServices;
using SysadminsLV.PKI.Management.CertificateServices.Database;
using SysadminsLV.PKI.Security.AccessControl;
using SysadminsLV.PKI.Win32;

namespace PKI.CertificateServices;

/// <summary>
/// The class represents Certification Authority (<strong>CA</strong>) object and contains related properties and methods.
/// </summary>
public class CertificateAuthority {
    readonly CertSrvConfigUtil _regReader;
    readonly ICertPropReaderD _propReader;
    Boolean[] keyMap;

    /// <param name="computerName">Specifies the fully qualified domain name (FQDN) of the computer where Certificate Services
    /// are installed.</param>
    /// <exception cref="ArgumentNullException">Te <strong>computerName</strong> parameter is null or empty.</exception>
    /// <exception cref="ServerUnavailableException">The computer specified in the <strong>computerName</strong>
    /// parameter could not be contacted via remote registry.</exception>
    [Obsolete("Deprecated. Use 'Connect(String)' static method instead.")]
    public CertificateAuthority(String computerName) {
        if (String.IsNullOrEmpty(computerName)) {
            throw new ArgumentNullException(nameof(computerName));
        }

        // temporary. Can be overwritten later from more trustworthy source (readInfoFromDsEntry)
        ComputerName = computerName;

        IsAccessible = Ping(computerName);
        _regReader = new CertSrvConfigUtil(computerName);
        // try to find in AD if possible
        ICertConfigEntryD dsEntry = lookInDs(computerName);
        // if we found in AD, then it is easy money. Or read directly from server
        if (dsEntry != null) {
            readInfoFromDsEntry(dsEntry);
            getDistinguishedName(dsEntry);
        } else {
            readInfoFromServer();
        }
        _propReader = new CertPropReaderD(ConfigString, false);
        // read other stuff
        initialize();
    }
    CertificateAuthority(ICertConfigEntryD entry) {
        IsAccessible = Ping(entry.ComputerName);
        // write basic info from ICertConfig without contacting the server.
        readInfoFromDsEntry(entry);
            
        _regReader = new CertSrvConfigUtil(ComputerName); // Cause delay 2x (1xRegistry, 1xDCOM)
        _propReader = new CertPropReaderD(ComputerName, false);

        // read other stuff
        initialize();
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
    /// unsuccessful, the code falls back to RPC/DCOM connections (by using <strong>ICertAdmin2</strong> COM interface) to
    /// get registry data.</para>
    /// </remarks>
    [Obsolete("Deprecated. Use 'Connect(String)' static method instead.", true)]
    public CertificateAuthority(String computerName, String name) : this(computerName) { }

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
    /// Indicates whether the Certification Authority is Enterprise CA (<strong>True</strong>) or Standalone CA (<strong>True</strong>).
    /// </summary>
    public Boolean IsEnterprise { get; private set; }
    /// <summary>
    /// Indicates whether the Certification Authority is root (<strong>True</strong>) or subordinate CA (<strong>True</strong>).
    /// </summary>
    public Boolean IsRoot { get; private set; }
    /// <summary>
    /// Gets operating system of the server which runs Certification Authority role.
    /// </summary>
    public String OperatingSystem { get; private set; }
    /// <summary>
    /// Gets accessibility status for Certification Authority. Returns <strong>True</strong> if Certification Authority is online and management
    /// interfaces are accessible, otherwise <strong>False</strong>.
    /// <para>This property does not indicate whether remote registry is available or not. Refer to <see cref="RegistryOnline"/>
    /// property to determine remote registry availability.</para>
    /// </summary>
    public Boolean IsAccessible { get; private set; }
    /// <summary>
    /// Gets remote registry accessibility status for Certification Authority. Returns <strong>True</strong> if Certification Authority
    /// if remote registry is accessible, otherwise <strong>False</strong>.
    /// <para>This property does not indicate whether management interfaces are available or not. Refer to <see cref="IsAccessible"/>
    /// property to determine management interface availability.</para>
    /// </summary>
    public Boolean RegistryOnline => _regReader.RegistryOnline;
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
    [Obsolete("Use 'GetBaseCRL()' method instead.", true)]
    public X509CRL2 BaseCRL => null;
    /// <summary>
    /// Gets the most recent Delta CRL. If CA server is not configured to use Delta CRLs, the property is empty.
    /// </summary>
    [Obsolete("Use 'GetDeltaCRL()' method instead.", true)]
    public X509CRL2 DeltaCRL => null;
    /// <summary>
    /// Gets or sets an array of Certification Authority's web services URI.
    /// </summary>
    [Obsolete("Use 'EnrollmentEndpoints' property instead.")]
    public CESUri[] EnrollmentServiceURI { get; set; }
    /// <summary>
    /// Gets a collection of Certification Authority's web services enrollment endpoints.
    /// </summary>
    public PolicyEnrollEndpointUriCollection EnrollmentEndpoints { get; }
        = new();
    internal CertSrvPlatformVersion Version { get; private set; }
    internal String Sku { get; private set; }

    static ICertConfigEntryD lookInDs(String computerName) {
        if (!DsUtils.Ping()) {
            // we are in workgroup, so try to get DsEntry from whatever source we have using the name caller specified
            return new CertConfigD().FindConfigEntryByServerName(computerName);
        }

        // we are connected to AD.
        // If name is passed in NetBIOS form, then translate to FQDN, because DS entries reference by FQDN only
        if (!computerName.Contains(".")) {
            computerName = $"{computerName}.{DsUtils.GetCurrentDomainName()}";
        }
        // try to find by FQDN
        return new CertConfigD().FindConfigEntryByServerName(computerName);
    }
    void initialize() {
        if (!_regReader.RegistryOnline && !_regReader.DcomOnline) {
            return;
        }

        getType();
        getVersion();
        getWmiData();
        getCaCertificate();
        buildKeyMap();
        getCertSvcServiceStatus();
    }
    void readInfoFromDsEntry(ICertConfigEntryD dsEntry) {
        ComputerName = dsEntry.ComputerName;
        Name = dsEntry.CommonName;
        DisplayName = dsEntry.DisplayName;
        ConfigString = dsEntry.ConfigString;

        if (dsEntry.WebEnrollmentServers != null) {
            EnrollmentEndpoints.AddRange(dsEntry.WebEnrollmentServers.Select(x => new PolicyEnrollEndpointUri(x)));
        }
    }
    void readInfoFromServer() {
        // at this point we can say that specified CA is not registered in AD or we are not connected there,
        // so try to connect to CA and read info directly from server.
        // Note: we do not read ComputerName from server. We are ok with supplied one if it works. If it doesn't, no one cares then.
        _regReader.SetRootNode(true);
        Name = DisplayName = _regReader.GetStringEntry("CommonName");
        ConfigString = ComputerName + "\\" + Name;
    }
    void getType() {
        _regReader.SetRootNode(true);
        Int32 type = _regReader.GetNumericEntry("CAType");
        switch (type) {
            case 0:
                Type = "Enterprise Root CA";
                IsEnterprise = true;
                IsRoot = true;
                break;
            case 1:
                Type = "Enterprise Subordinate CA";
                IsEnterprise = true;
                break;
            case 3:
                Type = "Standalone Root CA";
                IsRoot = true;
                break;
            case 4:
                Type = "Standalone Subordinate CA";
                break;
            default:
                Type = "Undefined";
                break;
        }
    }
    void getVersion() {
        _regReader.SetRootNode(false);
        switch (_regReader.GetNumericEntry("Version")) {
            case 0x00010001: Version = CertSrvPlatformVersion.Win2000; break;
            case 0x00020002: Version = CertSrvPlatformVersion.Win2003; break;
            case 0x00030001: Version = CertSrvPlatformVersion.Win2008; break;
            case 0x00040001: Version = CertSrvPlatformVersion.Win2008R2; break;
            case 0x00050001: Version = CertSrvPlatformVersion.Win2012; break;
            case 0x00060001: Version = CertSrvPlatformVersion.Win2012R2; break; // without [MSKB-3013769] can look like 2012 RTM
            // there are no functional changes between 2016 and 2019, so treat them both as 2016
            case 0x00070001: Version = CertSrvPlatformVersion.Win2016; break;
        }
        SetupStatus = (SetupStatusEnum)_regReader.GetNumericEntry("SetupStatus");
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
    void getCaCertificate() {
        if (!IsAccessible) {
            return;
        }

        Certificate = new X509Certificate2(_propReader.GetLatestCaCertificate());
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
    void getDistinguishedName(ICertConfigEntryD dsEntry) {
        if (dsEntry == null || (dsEntry.Flags & CertConfigLocation.DsEntry) == 0) {
            return;
        }
        // at this point we know that we are connected to AD and can try to lookup for DistinguishedName attribute.
        //Console.WriteLine($"DEBUG: user forest     : {DsUtils.GetCurrentForestName()}");
        //Console.WriteLine($"DEBUG: computer forest : {DsUtils.GetComputerForestName()}");
        //Console.WriteLine($"DEBUG: user domain     : {DsUtils.GetUserDomainName()}");
        //Console.WriteLine($"DEBUG: computer domain : {DsUtils.GetComputerDomainName()}");
        //Console.WriteLine($"DEBUG: domain path 1   : {String.Join(".", ComputerName.Split('.').Where((v, i) => i != 0))}");
        //Console.WriteLine($"DEBUG: domain path     : {String.Join(",DC=", ComputerName.Split('.').Where((v, i) => i != 0))}");
        //Console.WriteLine($"DEBUG: config context  : {DsUtils.ConfigContext}");
        //String domain = String.Join(",DC=", ComputerName.Split('.').Where((v, i) => i != 0));
        var dsEnroll = (DsCertEnrollContainer)DsPkiContainer.GetAdPkiContainer(DsContainerType.EnrollmentServices);
        DistinguishedName = dsEnroll.EnrollmentServers
            .FirstOrDefault(x => x.ComputerName.Equals(ComputerName, StringComparison.OrdinalIgnoreCase))
            ?.DistinguishedName;
        //Console.WriteLine($"DEBUG: full dn         : {dn}");
    }
    void buildKeyMap() {
        if (!IsAccessible) {
            return;
        }

        Int32 count = _propReader.GetCaCertificateCount();
        if (count < 0) {
            return;
        }
        keyMap = new Boolean[count];
        for (Int32 index = 0; index < count; index++) {
            keyMap[index] = _propReader.GetCrlState(index) == AdcsPropCrlState.Valid;
        }
    }

    X509CRL2 getCRL(Boolean delta) {
        if (!IsAccessible) {
            var e = new ServerUnavailableException(DisplayName);
            e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
            throw e;
        }

        Byte[] rawData = delta
            ? _propReader.GetLatestCertDeltaCrl()
            : _propReader.GetLatestCertBaseCrl();

        return rawData == null
            ? null
            : new X509CRL2(rawData);
    }

    internal Boolean[] GetKeyMap() {
        return keyMap;
    }
    internal String GetConfigEntry(String entry) {
        switch (entry) {
            case "CAServerName":
                return ComputerName;
            case "ServerShortName":
                return ComputerName.Split('.')[0];
            case "CommonName":
                return Name;
            case "CATruncatedName":
                return DsUtils.GetSanitizedName(Name);
            case "ConfigurationContainer":
                _regReader.SetRootNode(true);
                return _regReader.GetStringEntry("DSConfigDN");
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
    /// Otherwise the method always returns <strong>False</strong>, regardless of actual interface state.
    /// </remarks>
    [Obsolete("Use 'PingAdmin()' or 'PingRequest()' method instead.")]
    public Boolean Ping() {
        if (String.IsNullOrEmpty(ComputerName)) {
            throw new UninitializedObjectException();
        }

        return Ping(ComputerName);
    }
    /// <summary>
    /// Gets the availability and accessibility of ADCS Certification Authority administration and management RPC/DCOM interface.
    /// </summary>
    /// <exception cref="UninitializedObjectException">The <see cref="CertificateAuthority"/> object is not
    /// initialized through a class constructor.</exception>
    /// <returns>
    /// <strong>True</strong> if management interfaces are available and caller has permissions to access it, otherwise <strong>False</strong>.
    /// </returns>
    public Boolean PingAdmin() {
        if (String.IsNullOrEmpty(ComputerName)) {
            throw new UninitializedObjectException();
        }

        try {
            var propReader = new CertPropReaderD(ConfigString, true);
            propReader.GetProductVersionProperty();
            return true;
        } catch {
            return false;
        }
    }
    /// <summary>
    /// Gets the availability and accessibility of ADCS Certification Authority request RPC/DCOM interface.
    /// </summary>
    /// <exception cref="UninitializedObjectException">The <see cref="CertificateAuthority"/> object is not
    /// initialized through a class constructor.</exception>
    /// <returns>
    /// <strong>True</strong> if request interfaces are available and caller has permissions to access it, otherwise <strong>False</strong>.
    /// </returns>
    public Boolean PingRequest() {
        if (String.IsNullOrEmpty(ComputerName)) {
            throw new UninitializedObjectException();
        }

        try {
            var propReader = new CertPropReaderD(ConfigString, false);
            propReader.GetProductVersionProperty();
            return true;
        } catch {
            return false;
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
        if (String.IsNullOrEmpty(Name)) {
            throw new UninitializedObjectException();
        }
        if (!PingAdmin() && !PingRequest()) {
            var e = new ServerUnavailableException(DisplayName);
            e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
            throw e;
        }

        var certs = new X509Certificate2Collection();
        Int32 count = _propReader.GetCaCertificateCount();
        for (Int32 index = 0; index < count; index++) {
            certs.Add(new X509Certificate(_propReader.GetCaCertificate(index)));
        }
        return certs;
    }
    /// <summary>
    /// Retrieves the most recent 'CA Exchange' certificate. If the certificate does not exist, the method
    /// will instruct CA server to generate or enroll a new one.
    /// </summary>
    /// <exception cref="UninitializedObjectException">The object is not properly initialized.</exception>
    /// <exception cref="ServerUnavailableException">CA server is not accessible via RPC/DCOM.</exception>
    /// <exception cref="UnauthorizedAccessException">The caller do not have at least <strong>Read</strong> permissions.</exception>
    /// <returns>CA Exchange certificate.</returns>
    public X509Certificate2 GetCAExchangeCertificate() {
        if (String.IsNullOrEmpty(Name)) { throw new UninitializedObjectException(); }
        if (!PingAdmin() && !PingRequest()) {
            ServerUnavailableException e = new ServerUnavailableException(DisplayName);
            e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
            throw e;
        }

        return new X509Certificate2(_propReader.GetExchangeCertificate());
    }
    /// <summary>
    /// Returns the most recent version of Base CRL.
    /// </summary>
    /// <exception cref="UninitializedObjectException">
    ///     The object is not properly initialized.
    /// </exception>
    /// <exception cref="ServerUnavailableException">
    ///     CA server is not accessible via RPC/DCOM.
    /// </exception>
    /// <returns>Base CRL.</returns>
    public X509CRL2 GetBaseCRL() {
        return getCRL(false);
    }
    /// <summary>
    /// Returns the most recent version of Delta CRL. If Certification Authority is not configured for Delta CRL, the method returns null.
    /// </summary>
    /// <exception cref="UninitializedObjectException">
    ///     The object is not properly initialized.
    /// </exception>
    /// <exception cref="ServerUnavailableException">
    ///     CA server is not accessible via RPC/DCOM.
    /// </exception>
    /// <returns>Delta CRL.</returns>
    public X509CRL2 GetDeltaCRL() {
        return getCRL(true);
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
            IsAccessible = false;
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
            IsAccessible = true;
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
            IsAccessible = true;
        } finally { sc.Close(); }
    }
    /// <summary>
    /// Returns all roles granted on the CA to the caller.
    /// </summary>
    /// <exception cref="UninitializedObjectException">The object is not properly initialized.</exception>
    /// <exception cref="ServerUnavailableException">CA server is not accessible via RPC/DCOM.</exception>
    /// <exception cref="UnauthorizedAccessException">The caller do not have at least <strong>Read</strong> permissions.</exception>
    /// <returns>Granted roles.</returns>
    public CertSrvClientRole GetMyRoles() {
        if (String.IsNullOrEmpty(ConfigString)) {
            throw new UninitializedObjectException();
        }
        if (!IsAccessible) {
            ServerUnavailableException e = new ServerUnavailableException(DisplayName);
            e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
            throw e;
        }

        var CertAdmin = new CCertAdmin();
        return (CertSrvClientRole)CertAdmin.GetMyRoles(ConfigString);
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
        if (!PingAdmin()) {
            ServerUnavailableException e = new ServerUnavailableException(DisplayName);
            e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
            throw e;
        }
        ICertCrlAdminD crlAdmin = new CertCrlAdminD(ConfigString);
        if (updateFilesOnly) {
            crlAdmin.RepublishDistributionPoints();
        } else {
            if (deltaOnly) {
                crlAdmin.PublishDeltaCrl();
            } else {
                crlAdmin.PublishAllCrl();
            }
        }
    }
    /// <summary>
    /// Updates Enrollment Services URLs in the Active Directory.
    /// </summary>
    /// <exception cref="NotSupportedException">Enrollment Service URLs are not supported in workgroups.</exception>
    public void UpdateEnrollmentServiceUri() {
        if (String.IsNullOrEmpty(DistinguishedName)) {
            throw new NotSupportedException("Enrollment Service URLs are not supported in workgroups.");
        }

        DsUtils.SetEntryProperty(DistinguishedName, DsUtils.PropPkiEnrollmentServers, EnrollmentEndpoints.DsEncode());
    }
    /// <summary>
    /// Gets the access control list (<strong>ACL</strong>) for the current Certification Authority.
    /// </summary>
    /// <returns>An ACL object.</returns>
    /// <remarks>Returned object inherits from <see cref="CommonObjectSecurity"/> and implements common methods.</remarks>
    public CertSrvSecurityDescriptor GetSecurityDescriptor() {
        _regReader.SetRootNode(true);
        if (!_regReader.RegistryOnline && !_regReader.DcomOnline) {
            ServerUnavailableException e = new ServerUnavailableException(DisplayName);
            e.Data.Add(nameof(e.Source), OfflineSource.Registry | OfflineSource.DCOM);
            throw e;
        }

        var sd = new CertSrvSecurityDescriptor(this);
        sd.SetSecurityDescriptorBinaryForm(_regReader.GetBinaryEntry("Security"));
        return sd;
    }

    /// <summary>
    /// Attempts to check specified Certification Authority's management interfaces availability.
    /// </summary>
    /// <param name="computerName">CA's computer host name. Can be either short (NetBIOS) or fully qualified (FQDN) name.</param>
    /// <exception cref="ArgumentNullException">If the <strong>computerName</strong> parameter is null or empty.</exception>
    /// <returns><strong>True</strong> if management interfaces are available and accessible, otherwise <strong>False</strong>.</returns>
    public static Boolean Ping(String computerName) {
        if (String.IsNullOrEmpty(computerName)) {
            throw new ArgumentNullException(nameof(computerName));
        }

        CertAdm.CertSrvIsServerOnline(computerName, out Boolean online);
        return online;
    }
    /// <summary>
    /// Stops Certification Authority service on a specified server.
    /// </summary>
    /// <param name="computerName">CA's computer host name. Can be either short (NetBIOS) or fully qualified (FQDN) name.</param>
    /// <exception cref="InvalidOperationException">The service is already stopped.</exception>
    public static void Stop(String computerName) {
        using var sc = new ServiceController("CertSvc", computerName);
        if (sc.Status == ServiceControllerStatus.Running) {
            sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped);
        } else { throw new InvalidOperationException(); }
    }
    /// <summary>
    /// Starts Certification Authority service on a specified server.
    /// </summary>
    /// <param name="computerName">CA's computer host name. Can be either short (NetBIOS) or fully qualified (FQDN) name.</param>
    /// <exception cref="InvalidOperationException">The service is already running.</exception>
    public static void Start(String computerName) {
        using var sc = new ServiceController("CertSvc", computerName);
        if (sc.Status == ServiceControllerStatus.Stopped) {
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running);
        } else { throw new InvalidOperationException(); }
    }
    /// <summary>
    /// Restarts a specified Certification Authority service. This method restarts 'certsvc' service.
    /// </summary>
    /// <param name="computerName">CA's computer host name. Can be either short (NetBIOS) or fully qualified (FQDN) name.</param>
    public static void Restart(String computerName) {
        using var sc = new ServiceController("CertSvc", computerName);
        if (sc.Status == ServiceControllerStatus.Running) {
            sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped);
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running);
        } else {
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running);
        }
    }
    /// <summary>
    /// Connects to a specified Certification Authority server. This method allows you to connect to either
    /// Standalone CA or Enterprise CA.
    /// </summary>
    /// <param name="computerName">Specifies the computer name to connect.</param>
    /// <returns>A CertificationAuthority object.</returns>
    /// <exception cref="ArgumentNullException">If the <strong>computerName</strong> parameter is <strong>null</strong> or <strong>empty</strong>.</exception>
    public static CertificateAuthority Connect(String computerName) {
        if (String.IsNullOrEmpty(computerName)) {
            throw new ArgumentNullException(nameof(computerName));
        }

        return new CertificateAuthority(computerName);
    }
    /// <summary>
    /// Enumerates registered in Certification Authorities from the current Active Directory forest.
    /// </summary>
    /// <param name="findType">Specifies CA object search type. The search type can be either: <strong>Name</strong>
    /// or <strong>Server</strong>.</param>
    /// <param name="findValue">Specifies search pattern for a type specified in <strong>findType</strong> argument.
    /// Wildcard characters: * and ? are accepted.</param>
    /// <returns>An array of Certification Authorities.</returns>
    public static CertificateAuthority[] EnumEnterpriseCAs(String findType = "Server", String findValue = "*") {
        if (!DsUtils.Ping()) {
            throw new Exception("Non-domain environments are not supported.");
        }
        List<CertificateAuthority> CAs = new List<CertificateAuthority>();

        var certConfig = new CertConfigD();
            
        foreach (ICertConfigEntryD entry in certConfig.EnumConfigEntries()) {
            if (!entry.Flags.HasFlag(CertConfigLocation.DsEntry)) {
                continue;
            }

            Wildcard wildcard = new Wildcard(findValue, RegexOptions.IgnoreCase);
            switch (findType.ToLower()) {
                case "name":
                    if (!wildcard.IsMatch(entry.CommonName)) {
                        continue;
                    }
                    break;
                case "server":
                    if (!wildcard.IsMatch(entry.ComputerName)) {
                        continue;
                    }
                    break;
                default:
                    throw new ArgumentException("The value for 'findType' must be either 'Name' or 'Server'.");
            }
            CAs.Add(new CertificateAuthority(entry));
        }
        return CAs.ToArray();
    }
}