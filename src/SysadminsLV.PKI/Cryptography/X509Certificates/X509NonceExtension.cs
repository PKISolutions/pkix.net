using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Defines the <strong>id-pkix-ocsp-nonce</strong> extension (defined in <see href="http://tools.ietf.org/html/rfc2560">RFC2560</see>).
/// This class cannot be inherited.
/// </summary>
public sealed class X509NonceExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.OcspNonce, "OCSP Nonce");

    /// <summary>
    /// Initializes a new instance of the <strong>X509NonceExtension</strong> class.
    /// </summary>
    public X509NonceExtension() {
        m_initialize();
    }
    /// <param name="nonceValue">The encoded data to use to create the extension.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    public X509NonceExtension(AsnEncodedData nonceValue, Boolean critical) : base(_oid, nonceValue.RawData, critical) {
        Asn1Reader asn = new Asn1Reader(nonceValue.RawData);
        Value = AsnFormatter.BinaryToString(asn.GetPayload(), EncodingType.Hex);
    }

    /// <summary>
    /// Gets Nonce extension value. This value is equals to <see cref="DateTime.Ticks">Ticks</see> property of <see cref="DateTime"/> class.
    /// </summary>
    public String Value { get; private set; }

    void m_initialize() {
        Char[] nonceChars = DateTime.Now.Ticks.ToString(CultureInfo.InvariantCulture).ToCharArray();
        Critical = false;
        Oid = _oid;
        Byte[] charBytes = nonceChars.Select(Convert.ToByte).ToArray();
        Value = AsnFormatter.BinaryToString(charBytes, EncodingType.Hex);
        RawData = Asn1Utils.Encode(charBytes.ToArray(), 4);
    }
    /// <summary>
    /// Returns a formatted version of the Abstract Syntax Notation One (ASN.1)-encoded data as a string.
    /// </summary>
    /// <param name="multiLine"><strong>True</strong> if the return string should contain carriage returns; otherwise, <strong>False</strong>.</param>
    /// <returns>A formatted string that represents the Abstract Syntax Notation One (ASN.1)-encoded data.</returns>
    public override String Format(Boolean multiLine) {
        var SB = new StringBuilder();
        SB.Append("Nonce value: " + Value);
        if (multiLine) {
            SB.Append(Environment.NewLine);
        }
        return SB.ToString();
    }
}