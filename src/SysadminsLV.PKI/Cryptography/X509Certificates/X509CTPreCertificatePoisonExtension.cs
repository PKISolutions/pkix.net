using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;
/// <summary>
/// Represents an X.509 Certificate Transparency Pre-certificate poison extension.
/// </summary>
public sealed class X509CTPreCertificatePoisonExtension : X509Extension {
    static readonly List<Byte> _defaultValue = new() { 5, 0 };
    static readonly Oid _oid = new(X509ExtensionOid.CTPrecertificatePoison, "CT Precertificate Poison");
    readonly List<Byte> _value = new();

    /// <summary>
    /// Initializes a new instance of <strong>X509CTPreCertificatePoisonExtension</strong> extension with default values.
    /// Default value is ASN.1 NULL type and extension is marked critical.
    /// </summary>
    public X509CTPreCertificatePoisonExtension() : base(_oid, _defaultValue.ToArray(), true) {
        _value.AddRange(_defaultValue);
    }

    /// <summary>
    /// Initializes a new instance of the <strong>X509CTPreCertificatePoisonExtension</strong> class from an
    /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
    /// </summary>
    /// <param name="value">The encoded data to use to create the extension.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    public X509CTPreCertificatePoisonExtension(AsnEncodedData value, Boolean critical) : base(value, critical) {
        if (value == null) {
            throw new ArgumentNullException(nameof(value));
        }

        m_decode(value.RawData);
        Oid = _oid;
    }

    /// <summary>
    /// Gets the extension value.
    /// </summary>
    public Byte[] Value => _value.ToArray();

    void m_decode(IEnumerable<Byte> rawData) {
        _value.AddRange(rawData);
    }

    /// <inheritdoc />
    public override String Format(Boolean multiLine) {
        return multiLine
            ? $"Poison value={AsnFormatter.BinaryToString(Value, forceUpperCase: true) + Environment.NewLine}"
            : $"Poison value={AsnFormatter.BinaryToString(Value, format: EncodingFormat.NOCRLF, forceUpperCase: true)}";
    }
}
