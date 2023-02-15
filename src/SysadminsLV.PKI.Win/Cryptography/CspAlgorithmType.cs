namespace SysadminsLV.PKI.Cryptography {
	/// <summary>
	/// The AlgorithmType enumeration type specifies the intended purpose of a cryptographic algorithm supported
	/// by a cryptographic provider.
	/// </summary>
	public enum CspAlgorithmType {
		/// <summary>
		/// The algorithm type is not defined.
		/// </summary>
		Unknown					= 0,
		/// <summary>
		/// The algorithm is used for symmetric encryption. This includes the RC2, RC4, Data Encryption Standard (DES),
		/// 3DES, and AES algorithms.
		/// </summary>
		Cipher					= 1,
		/// <summary>
		/// The algorithm is used for hashing. This includes the MD2, MD4, SHA1, SHA256, SHA384, SHA512 MAC, and
		/// Hash-Based Message Authentication Code (HMAC) hash algorithms.
		/// </summary>
		Hash					= 2,
		/// <summary>
		/// The algorithm is used for public key encryption. This includes RSA.
		/// </summary>
		AsymmetricEncryption	= 3,
		/// <summary>
		/// The algorithm is used for key exchange. This includes the Diffie-Hellman algorithm and ECDH algorithm.
		/// </summary>
		SecretAgreement			= 4,
		/// <summary>
		/// The algorithm is used for signing. This includes the RSA algorithm, Digital Signature Algorithm (DSA),
		/// and ECDSA algorithm.
		/// </summary>
		Signature				= 5,
		/// <summary>
		/// The algorithm is used to generate a random number.
		/// </summary>
		RandomNumberGenerator	= 6,
	}
}
