using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography.X509Certificates; 

/// <summary>
/// Represents a <strong>CRL Number</strong> certificate revocation list extension.
/// </summary>
public sealed class X509CRLNumberExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.CRLNumber);

    //public X509CRLNumberExtension() { Oid = _oid; }
    /// <summary>
    /// Initializes a new instance of the <strong>X509CRLNumberExtension</strong> class from an
    /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
    /// </summary>
    /// <param name="value">The encoded data to use to create the extension.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    public X509CRLNumberExtension(AsnEncodedData value, Boolean critical) : base(value, critical) {
        m_decode(value.RawData);
        Oid = _oid;
    }
    /// <summary>
    /// Initializes a new instance of the <strong>X509CRLNumberExtension</strong> class from CRL sequential
    /// number and a value that identifies whether the extension is critical.
    /// </summary>
    /// <param name="crlNumber">CRL sequential number.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    public X509CRLNumberExtension(BigInteger crlNumber, Boolean critical) {
        Critical = critical;
        m_encode(crlNumber);
        Oid = _oid;
    }

    /// <summary>
    /// Gets the CRL sequence number.
    /// </summary>
    public BigInteger CRLNumber { get; private set; }

    void m_decode(Byte[] rawData) {
        if (rawData[0] != (Int32)Asn1Type.INTEGER) { throw new InvalidDataException("The data is invalid"); }
        CRLNumber = new Asn1Integer(rawData).Value;
    }
    void m_encode(BigInteger crlNumber) {
        CRLNumber = crlNumber;
        RawData = Asn1Utils.Encode(crlNumber.ToLittleEndianByteArray(), (Byte)Asn1Type.INTEGER);
    }
}