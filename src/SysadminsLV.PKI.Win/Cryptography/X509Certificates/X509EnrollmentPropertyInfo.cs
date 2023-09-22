using System;
using System.Text;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents certificate enrollment information when the certificate is pending for CA manager approval.
/// This information is used for enrollment API to determine request status and install issued certificate
/// when request is approved.
/// </summary>
/// <remarks>
/// No public constructors are defined. Objects of this class are created by calling
/// <see cref="X509Certificate2ExtensionsWin.GetCertificateContextProperty"/> or
/// <see cref="X509Certificate2ExtensionsWin.GetCertificateContextProperties"/> extension methods.
/// </remarks>
public class X509EnrollmentPropertyInfo {

    internal X509EnrollmentPropertyInfo(Byte[] bytes) {
        m_initialize(bytes);
    }

    /// <summary>
    /// Gets pending request ID in the CA database.
    /// </summary>
    public UInt32 RequestID { get; private set; }
    /// <summary>
    /// Gets the CA server host name.
    /// </summary>
    public String CAServerHostName { get; private set; }
    /// <summary>
    /// Gets the CA certificate name.
    /// </summary>
    public String CAName { get; private set; }
    /// <summary>
    /// Gets the friendly name of the pending request.
    /// </summary>
    public String FriendlyName { get; private set; }

    void m_initialize(Byte[] bytes) {
        RequestID = BitConverter.ToUInt32(bytes, 0);
        Int32 hostNameLength = BitConverter.ToInt32(bytes, 4) * 2;
        CAServerHostName = Encoding.Unicode.GetString(bytes, 8, hostNameLength).TrimEnd('\0');
        Int32 caNameLength = BitConverter.ToInt32(bytes, 8 + hostNameLength) * 2;
        CAName = Encoding.Unicode.GetString(bytes, 12 + hostNameLength, caNameLength).TrimEnd('\0');
        Int32 fnLength = BitConverter.ToInt32(bytes, 12 + hostNameLength + caNameLength) * 2;
        FriendlyName = Encoding.Unicode.GetString(bytes, 16 + hostNameLength + caNameLength, fnLength).TrimEnd('\0');
    }

    /// <inheritdoc />
    public override String ToString() {
        const String str = @"
RequestId: {0}
CA Host Name: {1}
CA Name: {2}
Friendly Name: {3}
";
        return String.Format(str, RequestID, CAServerHostName, CAName, FriendlyName);
    }
}