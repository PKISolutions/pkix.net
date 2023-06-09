namespace PKI.CertificateTemplates;
/// <summary>
/// Defines the purpose of the certificate template and private key.
/// </summary>
public enum CertificateTemplatePurpose {
    /// <summary>
    /// The private key is intended for encryption and decryption.
    /// </summary>
    Encryption                 = 1,
    /// <summary>
    /// The private key is intended for signing and non-repudiation only.
    /// </summary>
    Signature                  = 2,
    /// <summary>
    /// The private key is intended for both, encryption and signing operations.
    /// </summary>
    EncryptionAndSignature     = 4,
    /// <summary>
    /// The private key is intended for digital signature and smart card logon. No encryption operations are allowed.
    /// </summary>
    SignatureAndSmartCardLogon = 8
}