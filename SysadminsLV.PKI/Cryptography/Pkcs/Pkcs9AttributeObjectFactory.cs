using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.Pkcs;

/// <summary>
/// Represents a factory class for <see cref="Pkcs9AttributeObject"/> that allows to create
/// a new object from an enveloped PKCS#9 attribute.
/// </summary>
public static class Pkcs9AttributeObjectFactory {
    /// <summary>
    /// Creates a new instance of <see cref="Pkcs9AttributeObject"/> class from an enveloped
    /// ASN.1-encoded PKCS#9 attribute data.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded complete attribute envelope (including object identifier).</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException">
    ///     <strong>rawData</strong> is null.
    /// </exception>
    /// <exception cref="Asn1InvalidTagException">
    ///     <strong>rawData</strong> does not represent enveloped PKCS#9 attribute object.
    /// </exception>
    public static Pkcs9AttributeObject CreateFromAsn1(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        var asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        asn.MoveNext();
        Oid oid = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData());
        asn.MoveNextAndExpectTags(0x31);

        return new Pkcs9AttributeObject(oid, asn.GetPayload());
    }
}
