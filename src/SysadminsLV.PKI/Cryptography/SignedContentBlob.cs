using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// This class represents an encoded content to be signed and a BLOB to hold the signature.
/// The <see cref="ToBeSignedData"/> member is an encoded X.509 certificate, certificate revocation list
/// (<strong>CRL</strong>), certificate trust list (<strong>CTL</strong>) or certificate request.
/// </summary>
public class SignedContentBlob {
    ///  <summary>
    ///  Initializes a new instance of the <strong>SignedContentBlob</strong> class from a ASN.1-encoded byte array.
    ///  </summary>
    ///  <param name="rawData">
    /// 		ASN.1-encoded object that represents a <strong>SignedContentInfo</strong> structure.
    ///  </param>
    /// <param name="type">
    ///     Specifies the content type in the <strong>rawData</strong> parameter.
    /// </param>
    public SignedContentBlob(Byte[] rawData, ContentBlobType type) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }

        BlobType = type;
        switch (type) {
            case ContentBlobType.SignedBlob:
                m_decode(rawData);
                break;
            case ContentBlobType.ToBeSignedBlob:
                ToBeSignedData = rawData;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(type), type, null);
        }
    }

    /// <summary>
    /// Gets the current blob type.
    /// </summary>
    public ContentBlobType BlobType { get; private set; }
    /// <summary>
    /// A BLOB that has been encoded by using Distinguished Encoding Rules (DER) and that is to be signed.
    /// </summary>
    public Byte[] ToBeSignedData { get; private set; }
    /// <summary>
    /// An <see cref="AlgorithmIdentifier"/> object that contains the signature algorithm type and
    /// any associated additional parameters.
    /// </summary>
    public AlgorithmIdentifier SignatureAlgorithm { get; private set; }
    /// <summary>
    /// BLOB containing a signed hash of the encoded data.
    /// </summary>
    public Asn1BitString Signature { get; set; }

    /// <summary>
    /// Gets raw signature value without outer ASN.1 container.
    /// </summary>
    /// <returns>Raw signature.</returns>
    public Byte[] GetRawSignature() {
        if (SignatureAlgorithm.AlgorithmId.FriendlyName.ToUpper().Contains("DSA")) {
            var asn = new Asn1Reader(Signature.Value);

            asn.MoveNext();
            var r = asn.GetPayload().ToList();
            if (r[0] == 0) { r.RemoveAt(0); }

            asn.MoveNext();
            var s = asn.GetPayload().ToList();
            if (s[0] == 0) { s.RemoveAt(0); }

            var signature = new List<Byte>(r);
            signature.AddRange(s);
            return signature.ToArray();
        }

        return Signature.Value;
    }

    void m_decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        asn.MoveNextAndExpectTags(0x30);
        ToBeSignedData = asn.GetTagRawData();
        asn.MoveNextSiblingAndExpectTags(0x30);
        SignatureAlgorithm = new AlgorithmIdentifier(asn.GetTagRawData());
        asn.MoveNextSiblingAndExpectTags(Asn1Type.BIT_STRING);
        Signature = new Asn1BitString(asn);
    }

    /// <summary>
    /// Signs <see cref="ToBeSignedData"/> data by using client-provided message signer.
    /// </summary>
    /// <param name="signerInfo">Configured message signer object which is used to sign the data.</param>
    public void Sign(ICryptSigner signerInfo) {
        var signature = signerInfo.SignData(ToBeSignedData).ToList();
        if (signerInfo.PublicKeyAlgorithm.Value == AlgorithmOid.RSA) {
            signature.Insert(0, 0);
            Signature = new Asn1BitString(Asn1Utils.Encode(signature.ToArray(), (Byte)Asn1Type.BIT_STRING));
        } else {
            // ECDSA, DSA signature consist of two parts, r and s.
            Int32 divider = signature.Count / 2;
            var r = signature.Skip(0).Take(divider).ToList();
            // check if most significant bit is set to 1. If set, prepend value with extra 0 byte.
            if (r[0] > 127) { r.Insert(0, 0); }
            
            var s = signature.Skip(divider).Take(divider).ToList();
            // check if most significant bit is set to 1. If set, prepend value with extra 0 byte.
            if (s[0] > 127) { s.Insert(0, 0); }
            var builder = new List<Byte>();
            builder.AddRange(Asn1Utils.Encode(r.ToArray(), (Byte)Asn1Type.INTEGER));
            builder.AddRange(Asn1Utils.Encode(s.ToArray(), (Byte)Asn1Type.INTEGER));
            builder = new List<Byte>(Asn1Utils.Encode(builder.ToArray(), 48));
            builder.Insert(0, 0);
            Signature = new Asn1BitString(Asn1Utils.Encode(builder.ToArray(), (Byte)Asn1Type.BIT_STRING));
        }
        SignatureAlgorithm = signerInfo.GetAlgorithmIdentifier();
        BlobType = ContentBlobType.SignedBlob;
    }
    /// <summary>
    /// Hashes current blob in <see cref="ToBeSignedData"/> member, constructs algorithm identifier
    /// (usually, with "NoSign" suffix) and attaches hash value in the signature section.
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm to use for hashing.</param>
    /// <exception cref="ArgumentException">
    /// Hash algorithm is not valid or cannot be mapped to respective signature algorithm.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <strong>hashAlgorithm</strong> parameter is null.
    /// </exception>
    public void Hash(Oid hashAlgorithm) {
        if (hashAlgorithm == null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }
        Oid.FromOidValue(hashAlgorithm.Value, OidGroup.HashAlgorithm);
        Oid transformedOid = hashAlgorithm.MapHashToSignatureOid();
        using var hasher = HashAlgorithm.Create(hashAlgorithm.FriendlyName);
        if (hasher == null) {
            throw new ArgumentException("Specified hash algorithm is not valid hashing algorithm");
        }
        var signature = hasher.ComputeHash(ToBeSignedData).ToList();
        signature.Insert(0, 0);
        Signature = new Asn1BitString(Asn1Utils.Encode(signature.ToArray(), (Byte)Asn1Type.BIT_STRING));
        SignatureAlgorithm = new AlgorithmIdentifier(transformedOid, new Asn1Null().GetRawData());
        BlobType = ContentBlobType.SignedBlob;
    }
    /// <summary>
    /// Encodes current object to ASN-encoded signed blob object.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The TBS blob is not signed.
    /// </exception>
    /// <returns>ASN-encoded signed blob.</returns>
    public Byte[] Encode() {
        if (BlobType == ContentBlobType.ToBeSignedBlob) {
            throw new InvalidOperationException("The object is not signed");
        }

        return Asn1Builder.Create(ToBeSignedData)
            .AddDerData(SignatureAlgorithm.RawData)
            .AddDerData(Signature.GetRawData())
            .GetEncoded();
    }
}