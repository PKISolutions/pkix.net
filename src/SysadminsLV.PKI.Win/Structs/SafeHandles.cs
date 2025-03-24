using System;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using PKI.Structs;

namespace SysadminsLV.PKI.Structs;

/// <summary>
/// <para>
/// SafeCryptoApiBlobContext provides a SafeHandle class for an CRYPTOAPI_BLOB structure.
/// This can be used instead of the raw IntPtr to avoid races with the garbage
/// collector, ensuring that the CRYPTOAPI_BLOB object is not cleaned up from underneath you
/// while you are still using the handle pointer.
/// </para>
/// <para>
/// This safe handle type represents a native CRYPTOAPI_BLOB.
/// </para>
/// <para>
/// A SafeCRLHandleContext for an X509CRL2 can be obtained by calling the
/// <see cref="Wincrypt.CRYPTOAPI_BLOB.GetSafeContext" /> extension method.
/// </para>
/// </summary>
/// <permission cref="SecurityPermission">
///     The immediate caller must have SecurityPermission/UnmanagedCode to use this type.
/// </permission>
[SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
public sealed class SafeCryptoApiBlobContext : SafeHandleZeroOrMinusOneIsInvalid {
    /// <inheritdoc />
    internal SafeCryptoApiBlobContext(Wincrypt.CRYPTOAPI_BLOB blob) : base(true) {
        IntPtr blobPtr = Marshal.AllocHGlobal(Marshal.SizeOf(blob));
        Marshal.StructureToPtr(blob, blobPtr, false);
        SetHandle(blobPtr);
    }

    /// <inheritdoc />
    protected override Boolean ReleaseHandle() {
        if (!IsInvalid) {
            Marshal.FreeHGlobal(DangerousGetHandle());
            handle = IntPtr.Zero;

            return true;
        }

        return false;
    }
}