using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates; 

// https://msdn.microsoft.com/en-us/library/cc249813.aspx
/// <summary>
///     Represents CA Version extension that describes the CA certificate and CA private key index used in CA
///     certificate and when signing CRLs.
/// </summary>
/// <remarks>
///     Active Directory Certificate Services supports the renewal of a certification authority (CA). Renewal is
///     the issuing of a new certificate for the CA to extend the CA's life beyond the end date of its original
///     certificate.
///     <para>
///     Each renewal results in a new CA certificate; however, the administrator can either generate a new
///     public/private key pair or reuse the existing public/private key pair for the CA certificate. For
///     consistency and integrity, CA certificates and certificate revocation lists(CRL) issued by the CA before
///     its renewal will be available after the CA has been renewed. To make these available, Certificate Services
///     maintains an index of CA certificates, CRLs, and keys.
///     </para>
///     <para>
///     When CA server is installed, initial key pair is used and both have zero index. Each time CA certificate
///     is renewed (regardless whether the key pair is changed or not), CA certificate index is incremented
///     sequentially by one. CA private key index is changed only when new key pair is generated during CA
///     certificate renewal and is updated to match CA certificate index.
///     </para>
/// </remarks>
public sealed class X509CAVersionExtension : X509Extension {
    internal X509CAVersionExtension(Byte[] rawData, Boolean critical)
        : base(X509ExtensionOid.CAVersion, rawData, critical) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        m_decode();
    }
    /// <summary>
    /// Initializes a new instance of <strong>X509CAVersionExtension</strong> from CA certificate version and
    /// CA private key version.
    /// </summary>
    /// <param name="caVersion">Zero-based CA certificate version.</param>
    /// <param name="keyVersion">Zero-based CA private key version.</param>
    /// <param name="critical">
    /// <strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>. CA Version extension
    /// shall be marked <strong>non-critical</strong>.
    /// </param>
    public X509CAVersionExtension(UInt16 caVersion, UInt16 keyVersion, Boolean critical) {
        Critical = critical;
        m_initialize(caVersion, keyVersion);
    }
    /// <summary>
    /// Initializes a new instance of <strong>X509CAVersionExtension</strong> from ASN.1-encoded byte array.
    /// </summary>
    /// <param name="caVersion">
    /// The encoded data to use to create the extension.
    /// </param>
    /// <param name="critical">
    /// <strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
    /// </param>
    public X509CAVersionExtension(AsnEncodedData caVersion, Boolean critical) : this(caVersion.RawData, critical) { }

    /// <summary>
    /// Gets a zero-based CA certificate version.
    /// </summary>
    public Int32 CACertificateVersion { get; private set; }
    /// <summary>
    /// Gets a zero-based CA private key version.
    /// </summary>
    public Int32 CAKeyVersion { get; private set; }

    // here we use reduced encoding, that is, use minimum required bytes to encode extension value.
    void m_initialize(UInt16 caVersion, UInt16 keyVersion) {
        Oid = new Oid(X509ExtensionOid.CAVersion);
        CACertificateVersion = caVersion;
        CAKeyVersion = keyVersion;
        // max 2 bytes
        var certBytes = BitConverter.GetBytes((UInt16)CACertificateVersion).ToList();
        if (BitConverter.IsLittleEndian) {
            certBytes.Reverse();
        }
        if (keyVersion == 0) {
            if (CACertificateVersion == 0) {
                RawData = RawData = new Byte[] { 2, 1, 0 };
            } else {
                // truncate leading zero bytes. Only if key index is zero.
                RawData = Asn1Utils.Encode(certBytes.SkipWhile(x => x == 0).ToArray(), (Byte)Asn1Type.INTEGER);
            }
        } else {
            var keyBytes = BitConverter.GetBytes((UInt16)CAKeyVersion).ToList();
            if (BitConverter.IsLittleEndian) {
                keyBytes.Reverse();
            }
            // truncate leading zero bytes for key, cert bytes must be 2 bytes long.
            keyBytes = keyBytes.SkipWhile(x => x == 0).ToList();
            keyBytes.AddRange(certBytes);
            RawData = Asn1Utils.Encode(keyBytes.ToArray(), (Byte)Asn1Type.INTEGER);
        }
    }
    /* CA Version is a combination of two 16-bit integers. Upper 16 bits represent CA private key index, lower
     * 16 bits represent CA certificate index. Values can be encoded with minimum number of bytes. For example,
     * if CA private key index is zero, upper 16 bits can be ommited, or truncated to minimum bytes to encode
     * value. CA certificate index value can be truncated to single byte only when private key index is zero,
     * otherwise, 1 or 2 bytes are used to encode private key index and 2 bytes to encode certificate index.
     * We shall support various encoding options (full and reduced).
     *
     * CA Version is encoded maximum of 4 bytes. If encoded value is larger, both indexes are set to -1 and
     * shall be treated as invalid value.
     */
    void m_decode() {
        var asn = new Asn1Reader(RawData);
        Byte[] readBytes = new Byte[4];
        // handle invalid encoded value during decoding without throwing exceptions
        if (asn.PayloadLength > 4) {
            CACertificateVersion = -1;
            CAKeyVersion = -1;
            return;
        }
        // calculate padding bytes to get 4 bytes byte array to represent whole 32-bit integer
        Int32 diff = 4 - asn.PayloadLength;
        // copy encoded value at the end of destination array and reverse if necessary 
        asn.GetPayload().CopyTo(readBytes, diff);
        if (BitConverter.IsLittleEndian) {
            Array.Reverse(readBytes);
        }
        Int32 fullValue = BitConverter.ToInt32(readBytes, 0);
        CACertificateVersion = (UInt16)(UInt16.MaxValue & fullValue);
        CAKeyVersion = (UInt16)(UInt16.MaxValue & (fullValue >> 16));
    }
}