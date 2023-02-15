namespace SysadminsLV.PKI.Cryptography {
	/// <summary>
	/// specifies the type of cryptographic provider. Providers implement cryptographic standards and algorithms
	/// in software and hardware.
	/// </summary>
	public enum CspProviderType {
		/// <summary>
		/// No provider is identified.
		/// </summary>
		None					= 0,
		/// <summary>
		/// Supports the following algorithms:
		/// <list type="table">
		///		<listheader>
		/// 		<term>Operation Type</term>
		/// 		<description>Supported algorithms</description>
		/// 	</listheader>
		///		<item>
		/// 		<term>Encryption</term>
		/// 		<description>RC2 and RC4</description>
		/// 	</item>
		///		<item>
		/// 		<term>Hashing</term>
		/// 		<description>MD5 and SHA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Key Exchange</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Signatures</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///	</list>
		/// </summary>
		RsaFull					= 1,
		/// <summary>
		/// /// Supports the following algorithms:
		/// <list type="table">
		///		<listheader>
		/// 		<term>Operation Type</term>
		/// 		<description>Supported algorithms</description>
		/// 	</listheader>
		///		<item>
		/// 		<term>Hashing</term>
		/// 		<description>MD5 and SHA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Signatures</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///	</list>
		/// </summary>
		RsaSignature			= 2,
		/// <summary>
		/// This is a subset of the <strong>DSSDiffieHellman</strong> provider type. Supports the following algorithms:
		/// /// Supports the following algorithms:
		/// <list type="table">
		///		<listheader>
		/// 		<term>Operation Type</term>
		/// 		<description>Supported algorithms</description>
		/// 	</listheader>
		///		<item>
		/// 		<term>Hashing</term>
		/// 		<description>MD5 and SHA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Signatures</term>
		/// 		<description>RDigital Signature Standard (DSS)</description>
		/// 	</item>
		///	</list>
		/// </summary>
		DSS						= 3,
		/// <summary>
		/// Supports the Fortezza cryptographic card developed by NSA. This includes support for the following algorithms:
		/// /// <list type="table">
		///		<listheader>
		/// 		<term>Operation Type</term>
		/// 		<description>Supported algorithms</description>
		/// 	</listheader>
		///		<item>
		/// 		<term>Encryption</term>
		/// 		<description>Skipjack</description>
		/// 	</item>
		///		<item>
		/// 		<term>Hashing</term>
		/// 		<description>SHA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Key Exchange</term>
		/// 		<description>KEA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Signatures</term>
		/// 		<description>DSS</description>
		/// 	</item>
		///	</list>
		/// </summary>
		Fortezza				= 4,
		/// <summary>
		/// Supports cryptographic algorithms used by the Microsoft Exchange mail application and other applications
		/// compatible with Microsoft Mail. This includes the following:
		/// <list type="table">
		///		<listheader>
		/// 		<term>Operation Type</term>
		/// 		<description>Supported algorithms</description>
		/// 	</listheader>
		///		<item>
		/// 		<term>Encryption</term>
		/// 		<description>CAST</description>
		/// 	</item>
		///		<item>
		/// 		<term>Hashing</term>
		/// 		<description>MD5</description>
		/// 	</item>
		///		<item>
		/// 		<term>Key Exchange</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Signatures</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///	</list>
		/// </summary>
		MsExchange				= 5,
		/// <summary>
		/// Supports the Secure Sockets Layer protocol. This includes the following algorithms:
		/// <list type="table">
		///		<listheader>
		/// 		<term>Operation Type</term>
		/// 		<description>Supported algorithms</description>
		/// 	</listheader>
		///		<item>
		/// 		<term>Encryption</term>
		/// 		<description>variable</description>
		/// 	</item>
		///		<item>
		/// 		<term>Hashing</term>
		/// 		<description>variable</description>
		/// 	</item>
		///		<item>
		/// 		<term>Key Exchange</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Signatures</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///	</list>
		/// </summary>
		SSL						= 6,
		/// <summary>
		/// Supports RSA and Schannel protocols. This includes the following algorithms:
		/// <list type="table">
		///		<listheader>
		/// 		<term>Operation Type</term>
		/// 		<description>Supported algorithms</description>
		/// 	</listheader>
		///		<item>
		/// 		<term>Encryption</term>
		/// 		<description>RC4, Data Encryption Standard (DES), 3DES</description>
		/// 	</item>
		///		<item>
		/// 		<term>Hashing</term>
		/// 		<description>MD5 and SHA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Key Exchange</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Signatures</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///	</list>
		/// </summary>
		RsaSChannel				= 12,
		/// <summary>
		/// Supports the following algorithms:
		/// <list type="table">
		///		<listheader>
		/// 		<term>Operation Type</term>
		/// 		<description>Supported algorithms</description>
		/// 	</listheader>
		///		<item>
		/// 		<term>Encryption</term>
		/// 		<description>CYLINK_MEK</description>
		/// 	</item>
		///		<item>
		/// 		<term>Hashing</term>
		/// 		<description>MD5 and SHA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Key Exchange</term>
		/// 		<description>Diffie-Hellman algorithm</description>
		/// 	</item>
		///		<item>
		/// 		<term>Signatures</term>
		/// 		<description>DSS</description>
		/// 	</item>
		///	</list>
		/// </summary>
		DSSDiffieHellman		= 13,
		/// <summary>
		/// Microsoft currently does not provide a CSP of this type.
		/// </summary>
		ECDSASignature			= 14,
		/// <summary>
		/// Microsoft currently does not provide a CSP of this type.
		/// </summary>
		ECNRASignature			= 15,
		/// <summary>
		/// Microsoft currently does not provide a CSP of this type.
		/// </summary>
		ECDSAFull				= 16,
		/// <summary>
		/// Microsoft currently does not provide a CSP of this type.
		/// </summary>
		ECNRAFull				= 17,
		/// <summary>
		/// Supports the Diffie-Hellman and Schannel protocols. This includes the following algorithms:
		/// <list type="table">
		///		<listheader>
		/// 		<term>Operation Type</term>
		/// 		<description>Supported algorithms</description>
		/// 	</listheader>
		///		<item>
		/// 		<term>Encryption</term>
		/// 		<description>DES, 3DES</description>
		/// 	</item>
		///		<item>
		/// 		<term>Hashing</term>
		/// 		<description>MD5 and SHA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Key Exchange</term>
		/// 		<description>Diffie-Hellman algorithm</description>
		/// 	</item>
		///		<item>
		/// 		<term>Signatures</term>
		/// 		<description>DSS</description>
		/// 	</item>
		///	</list>
		/// </summary>
		DiffieHellmanSChannel	= 18,
		/// <summary>
		/// Microsoft currently does not provide a CSP of this type.
		/// </summary>
		SpyrusLynks				= 20,
		/// <summary>
		/// Microsoft currently does not provide a CSP of this type.
		/// </summary>
		RNG						= 21,
		/// <summary>
		/// Microsoft currently does not provide a CSP of this type.
		/// </summary>
		IntelSec				= 22,
		/// <summary>
		/// Microsoft currently does not provide a CSP of this type.
		/// </summary>
		ReplaceOWF				= 23,
		/// <summary>
		/// Supports the following algorithms:
		/// <list type="table">
		///		<listheader>
		/// 		<term>Operation Type</term>
		/// 		<description>Supported algorithms</description>
		/// 	</listheader>
		///		<item>
		/// 		<term>Encryption</term>
		/// 		<description>RC2, RC4, AES</description>
		/// 	</item>
		///		<item>
		/// 		<term>Hashing</term>
		/// 		<description>MD5 and SHA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Key Exchange</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///		<item>
		/// 		<term>Signatures</term>
		/// 		<description>RSA</description>
		/// 	</item>
		///	</list>
		/// </summary>
		RsaAes					= 24
	}
}
