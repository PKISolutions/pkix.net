using System;
using System.Runtime.InteropServices;
using System.Security.Permissions;

namespace SysadminsLV.PKI.Cryptography {
    /// <summary>
    /// <para>
    /// SafeUnicodeStringHandle provides a SafeHandle class for an unicode strings in unmanaged memory.
    /// This can be used instead of the raw IntPtr to avoid races with the garbage collector, ensuring
    /// that the string object is not cleaned up from underneath you while you are still using the handle pointer.
    /// </para>
    /// <para>
    /// This safe handle type represents a unicode string.
    /// </para>
    /// </summary>
    /// <permission cref="SecurityPermission">
    ///     The immediate caller must have SecurityPermission/UnmanagedCode to use this type.
    /// </permission>
    [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
    [HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
    public sealed class SafeUnicodeStringHandle : SafeHandle {
        /// <summary>
        /// Initializes a new instance of <strong>SafeUnicodeStringHandle</strong> class from a unicode string.
        /// </summary>
        /// <param name="s">Unicode string.</param>
        public SafeUnicodeStringHandle(String s) : base(IntPtr.Zero, true) {
            handle = Marshal.StringToHGlobalUni(s);
        }


        /// <inheritdoc />
        public override Boolean IsInvalid => handle == IntPtr.Zero;

        /// <inheritdoc />
        protected override Boolean ReleaseHandle() {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }
}
