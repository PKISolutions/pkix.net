using System;

namespace SysadminsLV.PKI.Enrollment;

/// <summary>
/// This enumeration contains values that specifies the type of certificates that can be installed.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum InstallResponseFlags {
    /// <summary>
    /// Do not install untrusted certificates or certificates for which there is no corresponding request.
    /// </summary>
    AllowNone                 = 0,
    /// <summary>
    /// Create the private key from the certificate response rather than from the dummy certificate. This makes the dummy
    /// certificate optional. If this value is not set, the dummy certificate must exist, and the private key is
    /// extracted from it.
    /// </summary>
    AllowNoOutstandingRequest = 1,
    /// <summary>
    /// Install untrusted end entity and certification authority certificates. Certification authority certificates include
    /// root and subordinate CA certificates. End entity certificates are installed to the personal store, and CA
    /// certificates are installed to the certification authority store.
    /// </summary>
    AllowUntrustedCertificate = 2,
    /// <summary>
    /// Perform the same action as the AllowUntrustedCertificate flag but also installs the certificate even if the certificate
    /// chain cannot be built because the root is not trusted.
    /// </summary>
    AllowUntrustedRoot = 4
}