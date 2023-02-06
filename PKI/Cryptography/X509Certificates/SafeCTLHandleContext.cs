using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Win32;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// <para>
    /// SafeCTLHandleContext provides a SafeHandle class for an <see cref="X509CertificateTrustList"/> context.
    /// This can be used instead of the raw IntPtr to avoid races with the garbage
    /// collector, ensuring that the X509Certificate object is not cleaned up from underneath you
    /// while you are still using the handle pointer.
    /// </para>
    /// <para>
    /// This safe handle type represents a native CTL_CONTEXT.
    /// </para>
    /// <para>
    /// A SafeCTLHandleContext for an X509CTL can be obtained by calling the <see
    /// cref="X509CTL.GetSafeContext" /> extension method.
    /// </para>
    /// </summary>
    /// <permission cref="SecurityPermission">
    ///     The immediate caller must have SecurityPermission/UnmanagedCode to use this type.
    /// </permission>
    [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
    public sealed class SafeCTLHandleContext : SafeHandleZeroOrMinusOneIsInvalid {
        SafeCTLHandleContext() : base(true) { }
        /// <summary>
        /// Releases unmanaged handle held by a Certificate Trust List object.
        /// </summary>
        /// <returns><strong>True</strong> if the handle is released successfully, otherwise, <strong>False</strong>.</returns>
        protected override Boolean ReleaseHandle() {
            return Crypt32.CertFreeCTLContext(handle);
        }
    }
}
