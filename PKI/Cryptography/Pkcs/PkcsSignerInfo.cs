using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.Pkcs;

/// <summary>
/// The <strong>SignerInfo2</strong> class represents a signer associated with a SignedCms object that represents
/// a CMS/PKCS #7 message.
/// </summary>
/// <remarks>This class is a replacement for a .NET <see cref="SignerInfo"/> class.</remarks>
public sealed class PkcsSignerInfo {

    /* https://tools.ietf.org/html/rfc5652
    SignerInfo ::= SEQUENCE {
        version                         CMSVersion,
        issuerAndSerialNumber           SignerIdentifier,
        digestAlgorithm                 DigestAlgorithmIdentifier,
        authenticatedAttributes   [0]   IMPLICIT Attributes OPTIONAL,
        digestEncryptionAlgorithm       DigestEncryptionAlgorithmIdentifier,
        encryptedDigest                 EncryptedDigest,
        unauthenticatedAttributes [1]   IMPLICIT Attributes OPTIONAL }

    SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier
    }


    */

    readonly X509AttributeCollection _authAttributes = new();
    readonly X509AttributeCollection _unauthAttributes = new();
    readonly List<Byte> _rawData = new();

    ///  <summary>
    ///  Initializes a new instance of the <strong>PkcsSignerInfo</strong> class from a ASN.1-encoded byte array.
    ///  </summary>
    ///  <param name="rawData">ASN.1-encoded byte array that represents current object.</param>
    /// <exception cref="ArgumentNullException"><strong>rawData</strong> is null or empty array.</exception>
    public PkcsSignerInfo(Byte[] rawData) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        decode(rawData);
    }
    ///  <summary>
    /// 		Initializes a new instance of the <strong>SignerInfo2</strong> class from a ASN.1-encoded byte array
    /// 		and certificate collection (chain) associated with a signer.
    ///  </summary>
    ///  <param name="rawData">ASN.1-encoded byte array that represents current object.</param>
    ///  <param name="certs">
    /// 		A collection of certificates that contains signer certificate and chain certificates.
    ///  </param>
    /// <exception cref="ArgumentNullException"><strong>rawData</strong> is null or empty array.</exception>
    internal PkcsSignerInfo(Byte[] rawData, X509Certificate2Collection certs) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        decode(rawData);
        if (certs == null || certs.Count == 0) { return; }
        X509Certificate2Collection finds;
        switch (Issuer.Type) {
            case SubjectIdentifierType.IssuerAndSerialNumber:
                finds = certs.Find(X509FindType.FindBySerialNumber, ((X509IssuerSerial)Issuer.Value).SerialNumber, false);
                if (finds.Count == 0) { return; }
                Certificate = finds[0];
                break;
            case SubjectIdentifierType.SubjectKeyIdentifier:
                finds = certs.Find(X509FindType.FindBySubjectKeyIdentifier, Issuer.Value, false);
                if (finds.Count == 0) { return; }
                Certificate = finds[0];
                break;
        }
    }

    /// <summary>
    ///		Gets the signer information version.
    /// </summary>
    /// <remarks>
    ///		The version determines whether the message is a PKCS #7 message or a Cryptographic Message Syntax (CMS)
    ///		message. CMS is a newer superset of PKCS #7.
    /// </remarks>
    public Int32 Version { get; private set; }
    /// <summary>
    ///		Gets the certificate identifier of the signer associated with the signer information.
    /// </summary>
    public PkcsSubjectIdentifier Issuer { get; private set; }
    /// <summary>
    ///		Gets the signing certificate associated with the signer information.
    /// </summary>
    public X509Certificate2 Certificate { get; }
    /// <summary>
    ///		Gets the <see cref="Oid"/> object that represents the hash algorithm used in the computation of the signatures.
    /// </summary>
    public AlgorithmIdentifier HashAlgorithm { get; private set; }
    /// <summary>
    ///		Gets the <see cref="Oid"/> object that represents the hash algorithm used in the computation of the
    ///		encrypted hash.
    /// </summary>
    public AlgorithmIdentifier EncryptedHashAlgorithm { get; private set; }
    /// <summary>
    ///		Gets the raw encrypted hash.
    /// </summary>
    public Byte[] EncryptedHash { get; private set; }
    /// <summary>
    ///		Gets the <see cref="X509AttributeCollection"/> collection of signed attributes that is associated with
    ///		the signer information. Signed attributes are signed along with the rest of the message content.
    /// </summary>
    public X509AttributeCollection AuthenticatedAttributes => new(_authAttributes);
    /// <summary>
    ///		Gets the <see cref="X509AttributeCollection"/> collection of unsigned attributes that is associated with
    ///		the <see cref="PkcsSignerInfo"/> content. Unsigned attributes can be modified without invalidating the
    ///		signature.
    /// </summary>
    public X509AttributeCollection UnauthenticatedAttributes => new(_unauthAttributes);
    /// <summary>
    /// Gets the ASN-encoded raw data associated with the current object.
    /// </summary>
    public Byte[] RawData => _rawData.ToArray();


    void decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        asn.MoveNext();
        Version = (Int32)Asn1Utils.DecodeInteger(asn.GetTagRawData());
        asn.MoveNextSibling();
        Issuer = new PkcsSubjectIdentifier(asn.GetTagRawData());
        asn.MoveNextSibling();
        HashAlgorithm = new AlgorithmIdentifier(asn.GetTagRawData());
        asn.MoveNextSibling();
        if (asn.Tag == 0xa0) {
            _authAttributes.Decode(asn.GetTagRawData());
            asn.MoveNextSibling();
        }
        EncryptedHashAlgorithm = new AlgorithmIdentifier(asn.GetTagRawData());
        asn.MoveNextSibling();
        EncryptedHash = asn.GetPayload();
        if (asn.MoveNextSibling() && asn.Tag == 0xa1) {
            _unauthAttributes.Decode(asn.GetTagRawData());
        }
        _rawData.AddRange(rawData);
    }

    /// <summary>
    /// Returns a string that represents the current object.
    /// </summary>
    /// <returns>A string that represents the current object.</returns>
    public override String ToString() {
        StringBuilder SB = new StringBuilder();
        return base.ToString();
    }
}