using System;
using System.Text;
using PKI.Enrollment.Policy;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents CEP enrollment property information when the certificate was requested by using
/// Certificate Enrollment Web Services ([MS-XCEP] and [MS-WSTEP]).
/// </summary>
/// <remarks>
/// No public constructors are defined. Objects of this class are created by calling
/// <see cref="X509Certificate2ExtensionsWin.GetCertificateContextProperty"/> or
/// <see cref="X509Certificate2ExtensionsWin.GetCertificateContextProperties"/> extension methods.
/// </remarks>
public class X509CEPEnrollmentPropertyInfo {
    internal X509CEPEnrollmentPropertyInfo(Byte[] bytes) {
        initialize(bytes);
        Version = 1;
    }

    /// <summary>
    /// Gets the version number. Currently, version is constant '1'.
    /// </summary>
    public Int32 Version { get; private set; }
    /// <summary>
    /// Gets the Url of the Certificate Enrollment Policy Server.
    /// </summary>
    public String PolicyServerUrl { get; private set; }
    /// <summary>
    /// Gets Certificate Enrollment Policy Server Url flags.
    /// </summary>
    public PolicyServerUrlFlagsEnum PolicyServerUrlFlags { get; private set; }
    /// <summary>
    /// Gets the authentication type used to authenticate at Certificate Enrollment Policy Server.
    /// </summary>
    public PolicyAuthenticationEnum PolicyServerAuthentication { get; private set; }
    /// <summary>
    /// Gets the policy ID.
    /// </summary>
    public String PolicyId { get; private set; }
    /// <summary>
    /// Gets the Enrollment Server Url
    /// </summary>
    public String EnrollmentServerUrl { get; private set; }
    /// <summary>
    /// Gets the authentication type used to authenticate at Enrollment Server.
    /// </summary>
    public PolicyAuthenticationEnum EnrollmentServerAuthentication { get; private set; }
    /// <summary>
    /// Gets the certificate request ID in the CA database.
    /// </summary>
    public UInt32 RequestID { get; private set; }

    void initialize(Byte[] bytes) {
        PolicyServerAuthentication = (PolicyAuthenticationEnum)BitConverter.ToInt32(bytes, 8);
        PolicyServerUrlFlags = (PolicyServerUrlFlagsEnum)BitConverter.ToInt32(bytes, 12);
        EnrollmentServerAuthentication = (PolicyAuthenticationEnum)BitConverter.ToInt32(bytes, 16);
        String str = Encoding.Unicode.GetString(bytes, 20, bytes.Length - 20);
        String[] tokens = str.Split('\0');
        PolicyServerUrl = tokens[0];
        EnrollmentServerUrl = tokens[2];
        PolicyId = tokens[1];
        RequestID = Convert.ToUInt32(tokens[3]);
    }

    /// <summary>
    /// Gets the textual representation of the current object.
    /// </summary>
    /// <returns>Textual representation of the current object.</returns>
    public override String ToString() {
        const String str = @"
Policy Server Url: {0}
Policy Id: {1}
Url Flags: {2}
Policy Server Authentication: {3}
Enrollment Server Url: {4}
Enrollment Server Authentication: {5}
Request Id: {6}
";
        return String.Format(str,
            PolicyServerUrl,
            PolicyId,
            PolicyServerUrlFlags,
            PolicyServerAuthentication,
            EnrollmentServerUrl,
            EnrollmentServerAuthentication,
            RequestID
        );
    }
}