using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Utils.CLRExtensions;
/// <summary>
/// Contains extension methods for <see cref="SysadminsLV.PKI.Cryptography.X509Certificates.X509CertificateTrustList"/>
/// </summary>
public static class X509CertificateTrustListExtensions {
    /// <summary>
    ///     Gets a <see cref="SafeCTLHandleContext" /> for the X509 certificate revocation list. The caller of this
    ///     method owns the returned safe handle, and should dispose of it when they no longer need it. 
    ///     This handle can be used independently of the lifetime of the original X509 certificate revocation list.
    /// </summary>
    /// <returns>Safe handle to a current CTL instance.</returns>
    /// <permission cref="SecurityPermission">
    ///     The immediate caller must have SecurityPermission/UnmanagedCode to use this method
    /// </permission>
    public static SafeCTLHandleContext GetSafeContext(this X509CertificateTrustList ctl) {
        SafeCTLHandleContext ctx = Crypt32.CertCreateCTLContext(65537, ctl.RawData, (UInt32)ctl.RawData.Length);
        GC.KeepAlive(ctl);
        return ctx;
    }
    /// <summary>
    /// Displays a X.509 Certificate Trust List UI dialog.
    /// </summary>
    public static void ShowUI(this X509CertificateTrustList ctl) {
        using SafeCTLHandleContext handle = ctl.GetSafeContext();
        CryptUI.CryptUIDlgViewContext(3, handle, IntPtr.Zero, "Certificate Trust List", 0, 0);
    }
}
