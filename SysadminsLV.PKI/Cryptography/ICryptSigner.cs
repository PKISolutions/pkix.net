using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Cryptography;
/// <summary>
/// Represents cryptographic message signing object contract.
/// </summary>
public interface ICryptSigner {
    /// <summary>
    /// Gets the certificate associated with the current instance of <strong>MessageSigner</strong>.
    /// </summary>
    X509Certificate2 SignerCertificate { get; }
    /// <summary>
    /// Gets public key algorithm.
    /// </summary>
    Oid PublicKeyAlgorithm { get; }
    /// <summary>
    /// Gets or sets the hashing algorithm that is used to calculate the hash during signing or signature verification
    /// processes.
    /// </summary>
    Oid HashingAlgorithm { get; set; }
    /// <summary>
    /// Gets resulting signature algorithm identifier.
    /// </summary>
    Oid SignatureAlgorithm { get; }
    /// <summary>
    /// Gets or sets signature padding scheme for RSA signature creation and validation.
    /// Default is <strong>PKCS1</strong>.
    /// </summary>
    RSASignaturePadding PaddingScheme { get; set; }
    /// <summary>
    /// Gets or sets the size, in bytes, of the random salt to use for the PSS padding.
    /// Default value matches the hash output length: 16 bytes for MD5, 20 bytes for SHA1, 32 bytes for
    /// SHA256, 48 bytes for SHA384 and 64 bytes for SHA512 hashing algorithm.
    /// </summary>
    Int32 PssSaltByteCount { get; set; }
    /// <summary>
    /// Signs the data with signer's private key and specified hash algorithm.
    /// </summary>
    /// <param name="message">Raw message to sign.</param>
    /// <exception cref="ArgumentNullException"><strong>message</strong> parameter is null.</exception>
    /// <returns>Raw signature.</returns>
    /// <remarks>For DSA private key only SHA1 hash is used.</remarks>
    Byte[] SignData(Byte[] message);
    /// <summary>
    /// Signs the hash with signer's private key.
    /// </summary>
    /// <param name="hash">Hash to sign.</param>
    /// <exception cref="ArgumentNullException"><strong>hash</strong> parameter is null.</exception>
    /// <returns>Raw signature.</returns>
    Byte[] SignHash(Byte[] hash);
    /// <summary>
    /// Verifies that the specified signature matches the specified hash.
    /// </summary>
    /// <param name="message">The data that was signed.</param>
    /// <param name="signature">The signature data to be verified.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>message</strong> or <strong>signature</strong> parameter is null.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if hash matches the one stored in signature, otherwise <strong>False</strong>.
    /// </returns>
    Boolean VerifyData(Byte[] message, Byte[] signature);
    /// <summary>
    /// Verifies that the specified signature matches the specified hash.
    /// </summary>
    /// <param name="hash">The hash value of the signed data.</param>
    /// <param name="signature">The signature data to be verified.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>hash</strong> or <strong>signature</strong> parameter is null.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if hash matches the one stored in signature, otherwise <strong>False</strong>.
    /// </returns>
    Boolean VerifyHash(Byte[] hash, Byte[] signature);
    /// <summary>
    /// Gets ASN-encoded algorithm identifier based on current configuration.
    /// </summary>
    /// <param name="alternate">
    /// Specifies whether alternate signature format is used. This parameter has meaning only for
    /// ECDSA keys. Otherwise, the parameter is ignored. Default value is <strong>false</strong>.
    /// </param>
    /// <returns>ASN-encoded algorithm identifier.</returns>
    AlgorithmIdentifier GetAlgorithmIdentifier(Boolean alternate = false);
}
