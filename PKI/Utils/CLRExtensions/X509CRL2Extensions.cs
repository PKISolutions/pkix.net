using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Utils.CLRExtensions;
public static class X509CRL2Extensions {
    /// <summary>
    ///     Gets a <see cref="SafeCRLHandleContext" /> for the X509 certificate revocation list. The caller of this
    ///     method owns the returned safe handle, and should dispose of it when they no longer need it. 
    ///     This handle can be used independently of the lifetime of the original X509 certificate revocation list.
    /// </summary>
    /// <returns>Handle to a <strong>CRL_CONTEXT</strong> structure.</returns>
    /// <permission cref="SecurityPermission">
    ///     The immediate caller must have SecurityPermission/UnmanagedCode to use this method
    /// </permission>
    public static SafeCRLHandleContext GetSafeContext(this X509CRL2 crl) {
        SafeCRLHandleContext ctx = Crypt32.CertCreateCRLContext(65537, crl.RawData, (UInt32)crl.RawData.Length);
        GC.KeepAlive(crl);
        return ctx;
    }
    /// <summary>
    /// Displays a X.509 Certificate Revocation List UI dialog.
    /// </summary>
    public static void ShowUI(this X509CRL2 crl) {
        using SafeCRLHandleContext handle = crl.GetSafeContext();
        CryptUI.CryptUIDlgViewContext(3, handle, IntPtr.Zero, "Certificate Trust List", 0, 0);
    }
}
