using System;

namespace SysadminsLV.PKI.Cryptography {
    /// <summary>
    /// <strong>AlgorithmOperationsEnumeration</strong> type specifies the operations that an algorithm can perform.
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para> 
    /// </summary>
    [Flags]
    public enum CspAlgorithmOperation {
        /// <summary>
        /// No operation is specified.
        /// </summary>
        None					= 0x00000000, // 0
        /// <summary>
        /// The algorithm can be used for symmetric encryption. This includes the RC2, RC4, Data Encryption Standard
        /// (DES), 3DED, and AES algorithms.
        /// </summary>
        Cipher					= 0x00000001, // 1
        /// <summary>
        /// The algorithm can be used for hashing. This includes the MD2, MD4, SHA1, SHA256, SHA384, SHA512 MAC, and
        /// Hash-Based Message Authentication Code (HMAC) hashing algorithms.
        /// </summary>
        Hashing					= 0x00000002, // 2
        /// <summary>
        /// The algorithm can be used for public key encryption. This includes RSA.
        /// </summary>
        AsymmetricEncryption	= 0x00000004, // 4
        /// <summary>
        /// The algorithm can used for key exchange. This includes the Diffie-Hellman algorithm and ECDH algorithm.
        /// </summary>
        SecretAgreement			= 0x00000008, // 8
        /// <summary>
        /// The algorithm can be used for signing. This includes the RSA algorithm, Digital Signature Algorithm (DSA),
        /// and ECDSA algorithm.
        /// </summary>
        Signing					= 0x00000010, // 16
        /// <summary>
        /// The algorithm can be used for public key encryption, key exchange, and signing. This is a bitwise-OR combination of the following constants:
        /// <list type="bullet">
        ///		<item>AsymmetricEncryption</item>>
        ///		<item>SecretAgreement</item>
        ///		<item>Signing</item>
        /// </list>
        /// </summary>
        AnyAsymmetricOperation	= AsymmetricEncryption | SecretAgreement | Signing, // 28
        /// <summary>
        /// The algorithm can be used to generate a random number.
        /// </summary>
        RandomNumberGeneration	= 0x00000020, // 32,
        /// <summary>
        /// Signature algorithms are preferred but not required. An encryption algorithm may be chosen instead.
        /// This is used when searching for cryptographic service provider (CSP) status information based on
        /// supported operational capability.
        /// </summary>
        PreferSignatureOnly		= 0x00200000, // 2097152,
        /// <summary>
        /// An encryption algorithm (such as that identified by the AnyAsymmetricOperation or SecretAgreement flags)
        /// is preferred but not required. A signature algorithm may be chosen instead. This is used when searching
        /// for CSP status information based on supported operational capability.
        /// </summary>
        PreferNonSignature		= 0x00400000, // 4194304,
        /// <summary>
        /// Only an algorithm that exactly matches the specified operations is selected.
        /// </summary>
        ExactMatch				= 0x00800000, // 8388608,
        /// <summary>
        /// Use to mask the algorithm operation preference.
        /// </summary>
        PreferenceMask			= 0x00e00000 // 14680064,
    }
}
