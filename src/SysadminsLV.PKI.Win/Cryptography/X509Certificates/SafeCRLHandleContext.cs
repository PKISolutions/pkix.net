using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using SysadminsLV.PKI.Utils.CLRExtensions;
using SysadminsLV.PKI.Win32;

namespace System.Security.Cryptography.X509Certificates;

/// <summary>
/// <para>
/// SafeCRLHandleContext provides a SafeHandle class for an X509CRL2 certificate revocation list context
/// as stored in its handle. This can be used instead of the raw IntPtr to avoid races with the garbage
/// collector, ensuring that the X509Certificate object is not cleaned up from underneath you
/// while you are still using the handle pointer.
/// </para>
/// <para>
/// This safe handle type represents a native CRL_CONTEXT.
/// </para>
/// <para>
/// A SafeCRLHandleContext for an X509CRL2 can be obtained by calling the <see
/// cref="X509CRL2Extensions.GetSafeContext" /> extension method.
/// </para>
/// </summary>
/// <permission cref="SecurityPermission">
///     The immediate caller must have SecurityPermission/UnmanagedCode to use this type.
/// </permission>
[SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
public sealed class SafeCRLHandleContext : SafeHandleZeroOrMinusOneIsInvalid {
    /// <inheritdoc />
    public SafeCRLHandleContext() : base(true) { }
    /// <summary>
    /// Releases persistent handle and frees allocated resources.
    /// </summary>
    /// <returns><strong>True</strong> if the operation succeeds, otherwise <strong>False</strong>.</returns>
    protected override Boolean ReleaseHandle() {
        return Crypt32.CertFreeCRLContext(handle);
    }
}