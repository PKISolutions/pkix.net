using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents X.500 Distinguished Name relative attribute.
/// </summary>
public sealed class X500RdnAttribute : AsnEncodedData {
    Asn1Type encodingTag;
    /// <summary>
    /// Initializes a new instance of the <strong>X500RdnAttribute</strong> class from attribute
    /// object identifier (OID) and RDN attribute value.
    /// </summary>
    /// <param name="oid">RDN attribute object identifier.</param>
    /// <param name="value">RDN attribute value.</param>
    internal X500RdnAttribute(Oid oid, String value) {
        Oid = oid;
        Value = value;
        encodingTag = Asn1Type.PrintableString;
    }
    /// <summary>
    /// Initializes a new instance of the <strong>X500RdnAttribute</strong> class from attribute
    /// object identifier (OID), RDN attribute value and ASN encoding type to use for encoding.
    /// </summary>
    /// <param name="oid">RDN attribute object identifier.</param>
    /// <param name="value">RDN attribute value.</param>
    /// <param name="encodingTag">ASN string type used to encode RDN attribute.</param>
    X500RdnAttribute(Oid oid, String value, Asn1Type encodingTag) : this(oid, value) {
        Oid = oid;
        Value = value;
    }
    /// <summary>
    /// Initializes a new instance of the <strong>X500RdnAttribute</strong> class from encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="System.ArgumentNullException"><strong>rawData</strong> parameter is null.</exception>
    public X500RdnAttribute(Byte[] rawData) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        m_decode(rawData);
    }

    /// <summary>
    /// Gets a value of RDN attribute.
    /// </summary>
    public String Value { get; private set; }

    // TODO
    void m_initizlie(Oid oid, String value, Asn1Type tag) {
        // dc -- IA5 String only
        // E -- IA5String only
    }
    void m_decode(Byte[] rawData) {
        Asn1Reader asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
        asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
        Oid = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData());
        asn.MoveNext();
        Asn1Type[] types = {
                               Asn1Type.IA5String,
                               Asn1Type.PrintableString,
                               Asn1Type.VisibleString,
                               Asn1Type.UTF8String,
                               Asn1Type.UniversalString,
                               Asn1Type.BMPString,
                               Asn1Type.TeletexString
                           };
        encodingTag = (Asn1Type)asn.Tag;
        Value = Asn1Utils.DecodeAnyString(asn.GetTagRawData(), types);
        RawData = rawData;
    }
    void validateTag(Oid oid, Asn1Type tag) {
        List<Asn1Type> tags = new List<Asn1Type> {
                                                     Asn1Type.TeletexString,
                                                     Asn1Type.PrintableString,
                                                     Asn1Type.UniversalString,
                                                     Asn1Type.UTF8String,
                                                     Asn1Type.BMPString,
                                                     Asn1Type.IA5String,
                                                 };
        if (!tags.Contains(tag)) { throw new ArgumentException("Specified ASN.1 tag is not supported."); }
        encodingTag = tag;
    }

    /// <inheritdoc cref="System.Security.Cryptography.AsnEncodedData.Format(Boolean)"/>
    public override String Format(Boolean multiLine) {
        if (RawData == null || RawData.Length == 0) {
            return base.Format(multiLine);
        }
        String ending = multiLine ? Environment.NewLine : String.Empty;
        return $"{Oid.Format(false)} = {Value}{ending}";
    }
}