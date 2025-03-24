using System;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using PKI.Structs;

namespace SysadminsLV.PKI.Structs;

/// <summary>
/// <para>
/// SafeUnmanagedContext provides a SafeHandle class for an unmanaged buffer.
/// This can be used instead of the raw IntPtr to avoid races with the garbage
/// collector, ensuring that the buffer object is not cleaned up from underneath you
/// while you are still using the handle pointer.
/// </para>
/// </summary>
/// <permission cref="SecurityPermission">
///     The immediate caller must have SecurityPermission/UnmanagedCode to use this type.
/// </permission>
[SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
public sealed class SafeUnmanagedContext : SafeHandleZeroOrMinusOneIsInvalid {
    SafeUnmanagedContext() : base(false) { }
    /// <inheritdoc />
    public SafeUnmanagedContext(Int32 pcbData) : base(true) {
        IntPtr blobPtr = Marshal.AllocHGlobal(pcbData);
        SetHandle(blobPtr);
    }

    /// <inheritdoc />
    /// <remarks>This method does not release unmanaged resources held by the object referenced by this handle.</remarks>
    protected override Boolean ReleaseHandle() {
        Marshal.FreeHGlobal(DangerousGetHandle());
        handle = IntPtr.Zero;

        return true;
    }

    public static SafeUnmanagedContext GetEmpty() {
        return new SafeUnmanagedContext();
    }
}
/// <summary>
/// <para>
/// SafeUnmanagedContext provides a SafeHandle class for an unmanaged buffer.
/// This can be used instead of the raw IntPtr to avoid races with the garbage
/// collector, ensuring that the buffer object is not cleaned up from underneath you
/// while you are still using the handle pointer.
/// </para>
/// </summary>
/// <permission cref="SecurityPermission">
///     The immediate caller must have SecurityPermission/UnmanagedCode to use this type.
/// </permission>
[SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
public sealed class SafeUnmanagedContext<TStruct> : SafeHandleZeroOrMinusOneIsInvalid where TStruct : struct {
    /// <inheritdoc />
    public SafeUnmanagedContext(TStruct Struct) : base(true) {
        IntPtr blobPtr = Marshal.AllocHGlobal(Marshal.SizeOf(Struct));
        Marshal.StructureToPtr(Struct, blobPtr, true);
        SetHandle(blobPtr);
    }

    /// <inheritdoc />
    /// <remarks>This method does not release unmanaged resources held by the object referenced by this handle.</remarks>
    protected override Boolean ReleaseHandle() {
        Marshal.FreeHGlobal(DangerousGetHandle());
        handle = IntPtr.Zero;

        return true;
    }
}

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
/// A SafeCryptoApiBlobContext for a Wincrypt.CRYPTOAPI_BLOB can be obtained by calling the
/// <see cref="Wincrypt.CRYPTOAPI_BLOB.GetSafeContext" /> method.
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
    /// <remarks>This method does not release unmanaged resources held by the object referenced by this handle.</remarks>
    protected override Boolean ReleaseHandle() {
        Marshal.FreeHGlobal(DangerousGetHandle());
        handle = IntPtr.Zero;

        return true;
    }
}