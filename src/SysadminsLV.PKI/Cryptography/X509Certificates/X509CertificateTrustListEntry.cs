using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.Pkcs;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a X.509 certificate trust list (<strong>CTL</strong>) entry element. Generally, this elements describes the
/// certificate in the trust list.
/// </summary>
public class X509CertificateTrustListEntry {
    readonly Pkcs9AttributeObjectCollection _attributes = new();

    /// <summary>
    /// Initializes a new instance of <strong>X509CertificateTrustListEntry</strong> class using an existing instance of X.509 certificate and hashing
    /// algorithm used to compute the hash.
    /// </summary>
    /// <param name="certificate">
    /// An instance of certificate associated with the current CTL entry.
    /// </param>
    /// <param name="hashAlgorithm">
    /// Specifies the hashing algorithm used to calculate the thumbprint. This parameter is optional. If not specified, or invalid hash
    /// algorithm is specified, default certificate hashing algorithm is used.
    /// </param>
    /// <exception cref="ArgumentNullException"><strong>certificate</strong> parameter is null.</exception>
    public X509CertificateTrustListEntry(X509Certificate2 certificate, Oid hashAlgorithm = null) {
        Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

        if (hashAlgorithm == null) {
            Thumbprint = Certificate.Thumbprint;
        } else {
            using var hasher = HashAlgorithm.Create(hashAlgorithm.FriendlyName);
            if (hasher == null) {
                throw new ArgumentException("Specified hashing algorithm doesn't belong to hashing algorithm group.");
            }
            Thumbprint = AsnFormatter.BinaryToString(hasher.ComputeHash(certificate.RawData), format:EncodingFormat.NOCRLF, forceUpperCase: true);
        }
    }
    /// <summary>
    /// Initializes a new instance of <strong>X509CertificateTrustListEntry</strong> class using a byte array that represents certificate's thumbprint.
    /// </summary>
    /// <param name="thumbprint">Byte array that represents certificate's thumbprint.</param>
    public X509CertificateTrustListEntry(Byte[] thumbprint) {
        if (thumbprint == null) {
            throw new ArgumentNullException(nameof(thumbprint));
        }
        Thumbprint = AsnFormatter.BinaryToString(thumbprint, format: EncodingFormat.NOCRLF, forceUpperCase: true);
    }
    /// <summary>
    /// Initializes a new instance of <strong>X509CertificateTrustListEntry</strong> class using a byte array that represents certificate's thumbprint.
    /// </summary>
    /// <param name="encodedData"></param>
    public X509CertificateTrustListEntry(AsnEncodedData encodedData) {
        if (encodedData == null) {
            throw new ArgumentNullException(nameof(encodedData));
        }
        decode(encodedData.RawData);
    }

    /// <summary>
    /// Gets certificate's thumbprint value.
    /// </summary>
    public String Thumbprint { get; private set; }
    /// <summary>
    /// Gets a collection of attributes associated with the current certificate.
    /// </summary>
    /// <remarks>Use <see cref="AddAttribute"/> method to modify attribute collection.</remarks>
    public Pkcs9AttributeObjectCollection Attributes => new(_attributes);
    /// <summary>
    /// Gets an instance of <see cref="X509Certificate2"/> object which is associated with the current trust list entry. This member may return
    /// <strong>null</strong> when certificate data is not available.
    /// </summary>
    public X509Certificate2 Certificate { get; internal set; }

    void decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        asn.MoveNextAndExpectTags(Asn1Type.OCTET_STRING);
        Thumbprint = AsnFormatter.BinaryToString(asn.GetPayload(), format:EncodingFormat.NOCRLF, forceUpperCase: true);
        // check if there are attributes
        if (asn.MoveNext() && asn.Tag == 49) {
            Byte[] attrBytes = asn.GetTagRawData();
            // in CTL attributes are encoded as SET, but we need SEQUENCE, so change first byte to SEQUENCE (48)
            attrBytes[0] = 48;
            var attributes = new Pkcs9AttributeObjectCollection();
            // decode attributes into collection
            attributes.Decode(attrBytes);
            // and then add decoded attributes to internal list.
            _attributes.AddRange(attributes);
        }
    }

    /// <summary>
    /// Adds new cryptographic attribute associated with the current certificate trust list item.
    /// </summary>
    /// <param name="attribute">Cryptographic attribute to add.</param>
    /// <exception cref="ArgumentNullException"><strong>attribute</strong> parameter is null.</exception>
    /// <remarks>
    /// If current list of attributes already contains attribute with same OID as in <strong>attribute</strong> parameter,
    /// existing attribute is overwritten with new one. Two or more attributes of same type are not allowed.
    /// </remarks>
    public void AddAttribute(Pkcs9AttributeObject attribute) {
        if (attribute == null) {
            throw new ArgumentNullException(nameof(attribute));
        }
        // if there is already same attribute (with same OID), remove old attribute and add new attribute
        // to avoid duplicates.
        for (Int32 index = 0; index < _attributes.Count; index++) {
            if (_attributes[index].Oid.Value == attribute.Oid.Value) {
                _attributes.RemoveAt(index);
                break;
            }
        }
        _attributes.Add(attribute);
    }

    /// <summary>
    /// Encodes current instance of CTL entry to ASN.1-encoded byte array.
    /// </summary>
    /// <returns>
    /// ASN.1-encoded byte array.
    /// </returns>
    public Byte[] Encode() {
        Byte[] thumbBytes = AsnFormatter.StringToBinary(Thumbprint, EncodingType.HexRaw);
        var retValue = new List<Byte>(Asn1Utils.Encode(thumbBytes, (Byte)Asn1Type.OCTET_STRING));
        if (_attributes.Count == 0) {
            return Asn1Utils.Encode(retValue.ToArray(), 48);
        }
        var asn = new Asn1Reader(Attributes.Encode());
        retValue.AddRange(Asn1Utils.Encode(asn.GetPayload(), 49));
        return Asn1Utils.Encode(retValue.ToArray(), 48);
    }

    /// <inheritdoc />
    public override String ToString() {
        return Thumbprint;
    }
}