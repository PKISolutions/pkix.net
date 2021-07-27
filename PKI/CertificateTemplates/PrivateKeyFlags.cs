using System;

namespace PKI.CertificateTemplates {
    /// <summary>
    /// Defines private key configuration settings in certificate templates.
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
    /// </summary>
    [Flags]
    public enum PrivateKeyFlags {
        /// <summary>
        /// This flag indicates that attestation data is not required when creating the certificate request.
        /// It also instructs the server to not add any attestation OIDs to the issued certificate.
        /// </summary>
        None                               = 0,
        /// <summary>
        /// This flag instructs the client to create a key archival certificate request.
        /// </summary>
        RequireKeyArchival                 = 0x00000001, // 1
        /// <summary>
        /// This flag instructs the client to allow other applications to copy the private key to a .pfx file at a later time.
        /// </summary>
        AllowKeyExport                     = 0x00000010, // 16
        /// <summary>
        /// This flag instructs the client to use additional protection for the private key.
        /// </summary>
        RequireStrongProtection            = 0x00000020, // 32
        /// <summary>
        /// This flag instructs the client to use an alternate signature format.
        /// </summary>
        RequireAlternateSignatureAlgorithm = 0x00000040, // 64
        /// <summary>
        /// This flag instructs the client to use the same key when renewing the certificate.
        /// <para><strong>Windows Server 2003, Windows Server 2008, Windows Server 2008 R2</strong> - this flag is not supported.</para>
        /// </summary>
        ReuseKeysRenewal                   = 0x00000080, // 128
        /// <summary>
        /// This flag instructs the client to process the msPKI-RA-Application-Policies attribute.
        /// <para><strong>Windows Server 2003, Windows Server 2008, Windows Server 2008 R2</strong> - this flag is not supported.</para>
        /// </summary>
        UseLegacyProvider                  = 0x00000100,  // 256
        /// <summary>
        /// This flag indicates that attestation based on the user's credentials is to be performed.
        /// </summary>
        TrustOnUse                         = 0x00000200,
        /// <summary>
        /// This flag indicates that attestation based on the hardware certificate of the Trusted Platform Module (TPM)
        /// is to be performed.
        /// </summary>
        ValidateCert                       = 0x00000400,
        /// <summary>
        /// This flag indicates that attestation based on the hardware key of the TPM is to be performed.
        /// </summary>
        ValidateKey                        = 0x00000800,
        /// <summary>
        /// This flag informs the client that it SHOULD include attestation data if it is capable of doing
        /// so when creating the certificate request. It also instructs the server that attestation might or
        /// might not be completed before any certificates can be issued.
        /// </summary>
        AttestationPreferred               = 0x00001000,
        /// <summary>
        /// This flag informs the client that attestation data is required when creating the certificate request.
        /// It also instructs the server that attestation must be completed before any certificates can be issued.
        /// </summary>
        AttestationRequired                = 0x00002000,
        /// <summary>
        /// This flag instructs the server to not add any certificate policy OIDs to the issued certificate even though
        /// attestation SHOULD be performed.
        /// </summary>
        AttestationWithoutPolicy           = 0x00004000,
        /// <summary>
        /// This flag indicates that the key is used for Windows Hello logon.
        /// </summary>
        HelloLogonKey                      = 0x00200000
    }
}
