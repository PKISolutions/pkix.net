using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using CERTADMINLib;
using PKI.CertificateServices;
using SysadminsLV.PKI.Dcom.Implementations;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Security.AccessControl;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Management.CertificateServices;

/// <summary>
/// Represents Microsoft Online Responder object. Online Responder is a Microsoft implementation of Online Certificate Status Protocol.
/// Using this class you can manage various aspects of Online Responder management.
/// </summary>
public class OcspResponder {
    const String SERVICE_NAME = "OcspSvc";
    #region config properties
    // items prefixed with 'MSFT_' are Microsoft properties. Custom properties are prefixed with ''
    const String MSFT_AUDIT_FILTER               = "AuditFilter";
    const String MSFT_ARRAY_CONTROLLER           = "ArrayController";
    const String MSFT_ARRAY_MEMBERS              = "ArrayMembers";
    const String MSFT_NUM_OF_THREADS             = "NumOfThreads";
    const String MSFT_MAX_NUM_OF_CACHE_ENTRIES   = "MaxNumOfCacheEntries";
    const String MSFT_LOG_LEVEL                  = "LogLevel";
    const String MSFT_DEBUG                      = "Debug";
    const String MSFT_ENROLL_POLL_INTERVAL       = "EnrollPollInterval";
    const String MSFT_REQUEST_FLAGS              = "RequestFlags";
    const String MSFT_MAX_INCOMING_MESSAGE_SIZE  = "MaxIncomingMessageSize";
    const String MSFT_NUM_OF_BACKEND_CONNECTIONS = "NumOfBackendConnections";
    const String MSFT_REFRESH_RATE               = "RefreshRate";
    const String MSFT_MAX_AGE                    = "MaxAge";
    const String MSFT_ISAPI_DEBUG                = "ISAPIDebug";
    const String MSFT_MAX_NUM_OF_REQUEST_ENTRIES = "MaxNumOfRequestEntries";
    #endregion
    // readonly fields
    readonly IOCSPAdmin _ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();

    OcspResponder(String serverName) {
        if (
            String.IsNullOrEmpty(serverName)
            || "localhost".Equals(serverName, StringComparison.OrdinalIgnoreCase)
            || Environment.MachineName.Equals(serverName, StringComparison.OrdinalIgnoreCase)
            || ".".Equals(serverName)) {
            serverName = Environment.MachineName;
        }

        _ocspAdmin.GetConfiguration(serverName, true);
        ComputerName = getComputerName(_ocspAdmin, serverName);
    }

    /// <summary>
    /// Gets the host name of Online Responder.
    /// </summary>
    public String ComputerName { get; }
    /// <summary>
    /// Indicates whether the OCSP service is running.
    /// </summary>
    public Boolean IsRunning => Ping(ComputerName);
    /// <summary>
    /// Indicates whether the current instance of Online Responder is Array Controller.
    /// </summary>
    public Boolean IsArrayController => ComputerName.Equals(readScalarValue<String>(MSFT_ARRAY_CONTROLLER), StringComparison.OrdinalIgnoreCase);
    /// <summary>
    /// Gets the Array Controller of the current Online Responder Array.
    /// </summary>
    public OcspResponderMemberInfo ArrayController => (OcspResponderMemberInfo)readValue(MSFT_ARRAY_CONTROLLER);
    /// <summary>
    /// Gets a list of array members of the current Online Responder Array.
    /// </summary>
    public OcspResponderMemberInfoCollection ArrayMembers => (OcspResponderMemberInfoCollection)readValue(MSFT_ARRAY_MEMBERS);
    /// <summary>
    /// Gets or sets the maximum number of request entries in OCSP request message. Default value is 1.
    /// </summary>
    /// <remarks>This property is supported only on Windows Server 2012 R2 and newer based Online Responders.</remarks>
    public Int32 MaxNumOfRequestEntries {
        get {
            Int32 maxEntries = readScalarValue<Int32>(MSFT_MAX_NUM_OF_REQUEST_ENTRIES);
            return maxEntries == 0
                ? 1
                : maxEntries;
        }
        set {
            if (value > 0 && value != MaxNumOfRequestEntries) {
                if (value == 1) {
                    deleteValue(MSFT_MAX_NUM_OF_REQUEST_ENTRIES);
                } else {
                    writeValue(MSFT_MAX_NUM_OF_REQUEST_ENTRIES, value);
                }
            }
        }
    }
    /// <summary>
    /// Gets or sets the maximum number of OCSP responses cached by Online Responder.
    /// </summary>
    /// <remarks>Recommended value is between 1,000 and 10,000 entries.</remarks>
    public Int32 MaxNumOfCacheEntries {
        get => readScalarValue<Int32>(MSFT_MAX_NUM_OF_CACHE_ENTRIES);
        set {
            if (value != readScalarValue<Int32>(MSFT_MAX_NUM_OF_CACHE_ENTRIES)) {
                writeValue(MSFT_MAX_NUM_OF_CACHE_ENTRIES, value);
            }
        }
    }
    /// <summary>
    /// Gets or sets the number of simultaneous OCSP requests that can be served by the Online Responder.
    /// </summary>
    public Int32 NumOfThreads {
        get => readScalarValue<Int32>(MSFT_NUM_OF_THREADS);
        set {
            if (value != NumOfThreads) {
                writeValue(MSFT_NUM_OF_THREADS, value);
            }
        }
    }
    /// <summary>
    /// Gets or sets the maximum size of OCSP request in bytes, that is allowed to be processed on the server.
    /// </summary>
    /// <remarks>
    /// <para>If value is zero (0), then server will attempt to process incoming request of any size.</para>
    /// <para>Average size of unsigned request with single certificate in request is around 80-100 bytes. Average size of signed request
    /// is around 2-4kb.
    /// </para>
    /// </remarks>
    public Int32 MaxRequestSize {
        get => readScalarValue<Int32>(MSFT_MAX_INCOMING_MESSAGE_SIZE);
        set {
            if (value != MaxRequestSize) {
                if (value == 0) {
                    deleteValue(MSFT_MAX_INCOMING_MESSAGE_SIZE);
                } else {
                    writeValue(MSFT_MAX_INCOMING_MESSAGE_SIZE, value);
                }
            }
        }
    }
    /// <summary>
    /// Gets or sets request handling configuration on Online Responder server.
    /// </summary>
    public OcspResponderRequestFlags RequestFlags {
        get => readScalarValue<OcspResponderRequestFlags>(MSFT_REQUEST_FLAGS);
        set {
            if (value != RequestFlags) {
                if (value == OcspResponderRequestFlags.None) {
                    deleteValue(MSFT_REQUEST_FLAGS);
                } else {
                    writeValue(MSFT_REQUEST_FLAGS, value);
                }
            }
        }
    }
    /// <summary>
    /// Gets or sets the set of flags that identify the responder events for which the security audit is performed. 
    /// </summary>
    public OcspResponderAuditFilter AuditFilter {
        get => readScalarValue<OcspResponderAuditFilter>(MSFT_AUDIT_FILTER);
        set {
            if (value != AuditFilter) {
                writeValue(MSFT_AUDIT_FILTER, value);
            }
        }
    }
    /// <summary>
    /// Gets or sets the logging level on Online Responder.
    /// </summary>
    public OcspResponderLogLevel LogLevel {
        get => readScalarValue<OcspResponderLogLevel>(MSFT_LOG_LEVEL);
        set {
            if (value != LogLevel) {
                if (value == OcspResponderLogLevel.Minimal) {
                    deleteValue(MSFT_LOG_LEVEL);
                } else {
                    writeValue(MSFT_LOG_LEVEL, value);
                }
            }
        }
    }
    /// <summary>
    /// Gets or sets the value whether the tracing for errors on Online Responder is enabled.
    /// </summary>
    public Boolean TraceDebugEnabled {
        get => readScalarValue<Int32>(MSFT_DEBUG) != 0;
        set {
            if (value != TraceDebugEnabled) {
                if (value) {
                    writeValue(MSFT_DEBUG, 0xffffffe3);
                } else {
                    deleteValue(MSFT_DEBUG);
                }
            }
        }
    }

    static String getComputerName(IOCSPAdmin ocspAdmin, String serverName) {
        // if serverName contains dot, then FQDN name is used, return it as is.
        if (serverName.Contains(".")) {
            return serverName;
        }

        // otherwise, short name is passed, so current computer domain/workgroup is assumed
        // retrieve domain suffix
        String domainSuffix = DsUtils.GetCurrentDomainName();
        // if empty, then current machine is not part of domain, so return host name
        if (String.IsNullOrEmpty(domainSuffix)) {
            return serverName;
        }

        return $"{serverName}.{domainSuffix}";
    }

    Object readValue(String propertyName) {
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            ocspAdmin.GetConfiguration(ComputerName, true);
            var prop = (IOCSPProperty)ocspAdmin.OCSPServiceProperties.ItemByName[propertyName];

            switch (prop.Name) {
                case MSFT_ARRAY_CONTROLLER:
                    return ComputerName.Equals(prop.Value.ToString(), StringComparison.OrdinalIgnoreCase)
                        ? new OcspResponderMemberInfo(ComputerName)
                        : new OcspResponderMemberInfo(prop.Value.ToString());
                case MSFT_ARRAY_MEMBERS:
                    var list = new OcspResponderMemberInfoCollection();
                    foreach (String arrayMember in (Object[])prop.Value) {
                        list.Add(new OcspResponderMemberInfo(arrayMember));
                    }

                    return list;
                default:
                    return prop.Value;
            }
        } catch (COMException ex) {
            // check if exception is ERROR_OBJECT_NOT_FOUND
            if (ex.ErrorCode == ErrorHelper.E_OBJECT_NOT_FOUND) {
                return default;
            }
            // otherwise, rethrow
            throw;
        } finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }
    T readScalarValue<T>(String propertyName) {
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            ocspAdmin.GetConfiguration(ComputerName, true);
            var prop = (IOCSPProperty)ocspAdmin.OCSPServiceProperties.ItemByName[propertyName];

            return (T)prop.Value;
        } catch (COMException ex) {
            // check if exception is ERROR_OBJECT_NOT_FOUND
            if (ex.ErrorCode == ErrorHelper.E_OBJECT_NOT_FOUND) {
                return default;
            }
            // otherwise, rethrow
            throw;
        } finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }
    void writeValue(String propertyName, Object value) {
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            ocspAdmin.GetConfiguration(ComputerName, true);
            try {
                var prop = (IOCSPProperty)ocspAdmin.OCSPServiceProperties.ItemByName[propertyName];
                prop.Value = value;
            } catch {
                // the property does not exist, so create it
                ocspAdmin.OCSPServiceProperties.CreateProperty(propertyName, value);
            }
            ocspAdmin.SetConfiguration(ComputerName, true);
        } finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }
    void deleteValue(String propertyName) {
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            ocspAdmin.GetConfiguration(ComputerName, true);
            try {
                var prop = (IOCSPProperty)ocspAdmin.OCSPServiceProperties.ItemByName[propertyName];
                ocspAdmin.OCSPServiceProperties.DeleteProperty(prop.Name);
            } catch (COMException ex) {
                // soft-fail only for ERROR_OBJECT_NOT_FOUND
                if (ex.ErrorCode != -2147020584) {
                    throw;
                }
            }
            ocspAdmin.SetConfiguration(ComputerName, true);
        } finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }

    void saveConfig() {
        _ocspAdmin.SetConfiguration(ComputerName, true);
    }

    /// <summary>
    /// Connects to a specified Online Responder instance.
    /// </summary>
    /// <param name="computerName">Host name where Online Responder service is installed.</param>
    /// <returns>An instance of Online Responder.</returns>
    public static OcspResponder Connect(String computerName) {
        return new OcspResponder(computerName);
    }
    /// <summary>
    /// Pings specified Online Responder server.
    /// </summary>
    /// <param name="computerName">Online Responder host name.</param>
    /// <returns>
    ///     <strong>True</strong> if Online Responder service is up and running. Otherwise <strong>False</strong>.
    /// </returns>
    public static Boolean Ping(String computerName) {
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            ocspAdmin.Ping(computerName);
            return true;
        } catch {
            return false;
        } finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }

    /// <summary>
    /// Makes current instance of Online Responder an Array Controller. If current instance is already a controller, the method does nothing.
    /// </summary>
    public void MakeArrayController() {
        if (IsArrayController) {
            return;
        }

        foreach (OcspResponderMemberInfo arrayMember in ArrayMembers) {
            try {
                OcspResponder ocsp = Connect(arrayMember.ComputerName);
                ocsp.writeValue(MSFT_ARRAY_CONTROLLER, ComputerName);
            } catch {}
        }
    }
    /// <summary>
    /// Gets revocation configurations assigned to this Online Responder.
    /// </summary>
    /// <returns>Collection of revocation configurations.</returns>
    public OcspResponderRevocationConfigurationCollection GetRevocationConfigurations() {
        var revConfigList = new OcspResponderRevocationConfigurationCollection();
        foreach (IOCSPCAConfiguration revConfig in _ocspAdmin.OCSPCAConfigurationCollection) {
            revConfigList.Add(new OcspResponderRevocationConfiguration(ComputerName, revConfig));
        }
        return revConfigList;
    }
    /// <summary>
    /// Gets security descriptor of the current instance of Online Responder.
    /// </summary>
    /// <returns></returns>
    public OcspResponderSecurityDescriptor GetSecurityDescriptor() {
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            var sd = new OcspResponderSecurityDescriptor(this);
            sd.SetSecurityDescriptorSddlForm(ocspAdmin.GetSecurity(ComputerName));
            return sd;
        } finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }
    /// <summary>
    /// Adds new revocation configuration to Online Responder.
    /// </summary>
    /// <param name="name">Revocation configuration name.</param>
    /// <param name="caCertificate">CA certificate, the configuration is created for.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>name</strong> or <strong>caCertificate</strong> parameter is null.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    ///     Configuration already exist.
    /// </exception>
    /// <exception cref="ServerUnavailableException">
    ///     Online Responder is unavailable.
    /// </exception>
    /// <returns>A blank instance of revocation configuration.</returns>
    public OcspResponderRevocationConfiguration AddRevocationConfiguration(String name, X509Certificate2 caCertificate) {
        if (String.IsNullOrEmpty(name)) {
            throw new ArgumentNullException(nameof(name));
        }
        if (String.IsNullOrWhiteSpace(name)) {
            throw new ArgumentException("Configuration name is empty string.");
        }
        if (caCertificate == null) {
            throw new ArgumentNullException(nameof(caCertificate));
        }
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            ocspAdmin.GetConfiguration(ComputerName, true);
            if (ocspAdmin.OCSPCAConfigurationCollection.Cast<IOCSPCAConfiguration>().Any(x => x.Identifier.Equals(name, StringComparison.CurrentCultureIgnoreCase))) {
                throw new InvalidOperationException("Configuration already exist.");
            }
        } catch (COMException ex) {
            if (ex.ErrorCode == ErrorHelper.E_INVALID_STATE) {
                throw new ServerUnavailableException(ComputerName);
            }
        }
        IOCSPCAConfiguration comConfig = ocspAdmin.OCSPCAConfigurationCollection.CreateCAConfiguration(name, caCertificate.RawData);
        OcspResponderRevocationConfiguration.InitializeDefaults(comConfig);
        ocspAdmin.SetConfiguration(ComputerName, true);
        return new OcspResponderRevocationConfiguration(ComputerName, comConfig);
    }
    /// <summary>
    /// Adds new revocation configuration to Online Responder to work with specified certification authority.
    /// </summary>
    /// <param name="name">Revocation configuration display name.</param>
    /// <param name="certificateAuthority">Certification Authority object associated with revocation configuration.</param>
    /// <returns>Created revocation configuration. Use this return value to configure the revocation configuration.</returns>
    public OcspResponderRevocationConfiguration AddRevocationConfiguration(String name, CertificateAuthority certificateAuthority) {
        if (String.IsNullOrEmpty(name)) {
            throw new ArgumentNullException(nameof(name));
        }
        if (String.IsNullOrWhiteSpace(name)) {
            throw new ArgumentException("Configuration name is empty string.");
        }
        if (certificateAuthority == null) {
            throw new ArgumentNullException(nameof(certificateAuthority));
        }
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            ocspAdmin.GetConfiguration(ComputerName, true);
            if (ocspAdmin.OCSPCAConfigurationCollection.Cast<IOCSPCAConfiguration>().Any(x => x.Identifier.Equals(name, StringComparison.CurrentCultureIgnoreCase))) {
                throw new InvalidOperationException("Configuration already exist.");
            }
        } catch (COMException ex) {
            if (ex.ErrorCode == ErrorHelper.E_INVALID_STATE) {
                throw new ServerUnavailableException(ComputerName);
            }
        }
        IOCSPCAConfiguration comConfig = ocspAdmin.OCSPCAConfigurationCollection.CreateCAConfiguration(name, certificateAuthority.Certificate.RawData);
        OcspResponderRevocationConfiguration.InitializeDefaults(comConfig, certificateAuthority.ConfigString);
        ocspAdmin.SetConfiguration(ComputerName, true);
        return new OcspResponderRevocationConfiguration(ComputerName, comConfig);
    }
    /// <summary>
    /// Removes named revocation configuration from Online Responder.
    /// </summary>
    /// <param name="name">Configuration name to remove.</param>
    /// <exception cref="ArgumentException">
    ///     Specified revocation configuration is not valid.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    ///     <strong>name</strong> parameter is null.
    /// </exception>
    public void RemoveRevocationConfiguration(String name) {
        if (name == null) {
            throw new ArgumentNullException(nameof(name));
        }

        Boolean found = _ocspAdmin.OCSPCAConfigurationCollection
            .Cast<IOCSPCAConfiguration>()
            .Any(x => x.Identifier.Equals(name, StringComparison.CurrentCultureIgnoreCase));
        if (found) {
            _ocspAdmin.OCSPCAConfigurationCollection.DeleteCAConfiguration(name);
            saveConfig();
        } else {
            throw new ArgumentException("Specified revocation configuration is not valid.");
        }
    }
    /// <summary>
    /// Removes named revocation configuration from Online Responder.
    /// </summary>
    /// <param name="revConfig">Existing revocation configuration.</param>
    /// <exception cref="ArgumentException">
    ///     Specified revocation configuration is not valid.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    ///     <strong>name</strong> parameter is null.
    /// </exception>
    public void RemoveRevocationConfiguration(OcspResponderRevocationConfiguration revConfig) {
        if (revConfig == null) {
            throw new ArgumentNullException(nameof(revConfig));
        }
        RemoveRevocationConfiguration(revConfig.Name);
    }
    /// <summary>
    /// Removes all revocation configurations on a current Online Responder server.
    /// </summary>
    public void ClearRevocationConfigurations() {
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            ocspAdmin.GetConfiguration(ComputerName, true);
            IEnumerable<String> revConfigs = ocspAdmin.OCSPCAConfigurationCollection
                .Cast<IOCSPCAConfiguration>()
                .Select(x => x.Identifier);

            foreach (String revConfig in revConfigs) {
                ocspAdmin.OCSPCAConfigurationCollection.DeleteCAConfiguration(revConfig);
            }
            ocspAdmin.SetConfiguration(ComputerName, true);
        } finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }
    /// <summary>
    /// Adds specified Online Responder to the current Online Responder Array.
    /// </summary>
    /// <param name="responder">Online Responder instance to add.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>responder</strong> parameter is null;
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     Specified Online Responder is already part of this array.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    ///     This action must be executed on array controller.
    /// </exception>
    public void AddArrayMember(OcspResponder responder) {
        if (responder == null) {
            throw new ArgumentNullException(nameof(responder));
        }
        if (!IsArrayController) {
            throw new UnauthorizedAccessException("This action must be executed on array controller.");
        }
        if (ArrayMembers.Any(x => x.ComputerName.Equals(responder.ComputerName))) {
            throw new ArgumentException("Specified Online Responder is already part of this array.");
        }

        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            // plan
            // 1. remove all configurations from target server
            // 2. replace array controller on target server
            // 3. overwrite the list of array members on target and current servers.
            // 4. we should copy revocation configurations from current server to destination, but it can be done via MMC?

            // 1.
            responder.ClearRevocationConfigurations();
            // 2.
            responder.writeValue(MSFT_ARRAY_CONTROLLER, ComputerName);
            // 3.
            List<String> arrayMembers = ArrayMembers.Select(x => x.ComputerName).ToList();
            arrayMembers.Add(responder.ComputerName);
            writeValue(MSFT_ARRAY_MEMBERS, arrayMembers.ToArray());
            responder.writeValue(MSFT_ARRAY_MEMBERS, arrayMembers.ToArray());
            responder.Restart();
        } finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }
    /// <summary>
    /// Removes specified Online Responder from current Online Responder Array.
    /// </summary>
    /// <param name="computerName">Online Responder computer name.</param>
    /// <exception cref="ArgumentException">
    ///     Specified OCSP server is not part of current array.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    ///     This action must be executed on array controller.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    ///     <strong>computerName</strong> parameter is null.
    /// </exception>
    /// <remarks>
    /// When removing responder, the method attempts to contact requested responder and:
    /// <list type="number">
    ///     <item>Clear all revocation configurations;</item>
    ///     <item>Remove all array members;</item>
    ///     <item>Make itself as the only array member;</item>
    ///     <item>Promote to array controller.</item>
    /// </list>
    /// </remarks>
    public void RemoveArrayMember(String computerName) {
        if (computerName == null) {
            throw new ArgumentNullException(nameof(computerName));
        }
        if (!IsArrayController) {
            throw new UnauthorizedAccessException("This action must be executed on array controller.");
        }
        OcspResponderMemberInfo remoteOcspInfo = ArrayMembers.FirstOrDefault(x => x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase));
        if (remoteOcspInfo == null) {
            throw new ArgumentException("Specified OCSP server is not part of current array.");
        }

        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            // the plan is follows:
            // 1. remove all configurations from target server 
            // 2. remove all entries from array members
            // 3. promote to array controller
            // 4. remove server from current array

            try {
                OcspResponder remote = Connect(computerName);
                // 1.
                remote.ClearRevocationConfigurations();
                // 2.
                remote.writeValue(MSFT_ARRAY_MEMBERS, new[] { remote.ComputerName });
                // 3.
                remote.MakeArrayController();
                remote.Restart();
            } catch { }

            // 4.
            writeValue(
                MSFT_ARRAY_MEMBERS,
                ArrayMembers
                    .Select(x => x.ComputerName)
                    .Except([remoteOcspInfo.ComputerName])
                    .ToArray());
        } finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }

    /// <summary>
    /// Gets current client role on Online Responder server.
    /// </summary>
    /// <returns></returns>
    public OcspResponderClientRole GetMyRoles() {
        IOCSPAdmin ocspAdmin = CertAdminFactory.CreateIOCSPAdmin();
        try {
            return (OcspResponderClientRole) ocspAdmin.GetMyRoles(ComputerName);
        }
        finally {
            CryptographyUtils.ReleaseCom(ocspAdmin);
        }
    }
    /// <summary>
    /// Stops Online Responder service.
    /// </summary>
    /// <exception cref="InvalidOperationException">The service is already stopped.</exception>
    public void Stop() {
        using var sc = new ServiceController(SERVICE_NAME, ComputerName);
        if (sc.Status == ServiceControllerStatus.Running) {
            sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped);
            sc.Close();
        } else {
            throw new InvalidOperationException();
        }
    }
    /// <summary>
    /// Starts Online Responder service.
    /// </summary>
    /// <exception cref="InvalidOperationException">The service is already running or pending.</exception>
    public void Start() {
        using var sc = new ServiceController(SERVICE_NAME, ComputerName);
        if (sc.Status == ServiceControllerStatus.Stopped) {
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running);
            sc.Close();
        } else {
            throw new InvalidOperationException();
        }
    }
    /// <summary>
    /// Restarts current Online Responder instance.
    /// </summary>
    public void Restart() {
        using var sc = new ServiceController(SERVICE_NAME, ComputerName);
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
}