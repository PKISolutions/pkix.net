using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.Pkcs;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a managed PKCS #10 request.
/// </summary>
public class X509CertificateRequestPkcs10 {
    protected readonly Pkcs9AttributeObjectCollection InternalAttributes = new();
    protected readonly X509ExtensionCollection InternalExtensions = new();

    /// <summary>
    /// Initializes a new empty instance of <strong>X509CertificateRequestPkcs10</strong> class.
    /// </summary>
    /// <remarks>
    /// This constructor is useful for inheritors when PKCS#10 is not directly available to inheritors and they
    /// need to perform extra actions to get the right data. Once get, use <see cref="Decode"/> protected method
    /// to populate the data.
    /// </remarks>
    protected X509CertificateRequestPkcs10() { }
    /// <summary>
    /// Initializes a new instance of <strong>X509CertificateRequestPkcs10</strong> class from ASN.1-encoded
    /// byte array that represents PKCS #10 certificate request.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    public X509CertificateRequestPkcs10(Byte[] rawData) {
        Decode(rawData);
    }

    /// <summary>
    /// Gets the X.509 format version of a certificate request.
    /// </summary>
    /// <remarks>
    /// Currently only version 1 is defined.
    /// </remarks>
    public Int32 Version { get; protected set; }
    /// <summary>
    /// Gets the distinguished name of the request subject.
    /// </summary>
    public X500DistinguishedName SubjectName { get; protected set; }
    /// <summary>
    /// Gets textual form of the distinguished name of the request subject.
    /// </summary>
    public String Subject => SubjectName?.Name;
    /// <summary>
    /// Gets a <see cref="PublicKey"/> object associated with a certificate
    /// </summary>
    /// <remarks>
    /// <para>
    /// This property returns a PublicKey object, which contains the object identifier (Oid) representing the public key
    /// algorithm, the ASN.1-encoded parameters, and the ASN.1-encoded key value.</para>
    /// <para>You can also obtain the key as an <see cref="AsymmetricAlgorithm"/> object by referencing the <strong>PublicKey</strong> property.
    /// This property supports only RSA or DSA keys, so it returns either an <see cref="RSACryptoServiceProvider"/> or a
    /// <see cref="DSACryptoServiceProvider"/> object that represents the public key.</para>
    /// </remarks>
    public PublicKey PublicKey { get; protected set; }
    /// <summary>
    /// Gets a collection of <see cref="X509Extension"/> objects included in the request.
    /// </summary>
    public X509ExtensionCollection Extensions => InternalExtensions.Duplicate();
    /// <summary>
    /// Gets <see cref="Pkcs9AttributeObjectCollection"/> object that contains a collection of attributes
    /// associated with the certificate request.
    /// </summary>
    public Pkcs9AttributeObjectCollection Attributes => new(InternalAttributes);
    /// <summary>
    /// Gets the algorithm used to create the signature of a certificate request.
    /// </summary>
    /// <remarks>The object identifier <see cref="Oid">(Oid)</see> identifies the type of signature
    /// algorithm used by the certificate request.</remarks>
    public Oid SignatureAlgorithm { get; protected set; }
    /// <summary>
    /// Gets request signature status. Returns <strong>True</strong> if signature is valid, <strong>False</strong> otherwise.
    /// </summary>
    public Boolean SignatureIsValid { get; protected set; }
    /// <summary>
    /// Gets the raw data of a certificate request.
    /// </summary>
    public Byte[] RawData { get; protected set; }
    /// <summary>
    /// Populates current object with data from ASN.1-encoded byte array that represents encoded PKCS#10
    /// certificate request.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null.</exception>
    protected void Decode(Byte[] rawData) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        var blob = new SignedContentBlob(rawData, ContentBlobType.SignedBlob);
        // at this point we can set signature algorithm and populate RawData
        SignatureAlgorithm = blob.SignatureAlgorithm.AlgorithmId;
        var asn = new Asn1Reader(blob.ToBeSignedData);
        getVersion(asn);
        getSubject(asn);
        getPublicKey(asn);
        // if we reach this far, then we can verify request attribute.
        SignatureIsValid = PublicKey.VerifySignature(blob);
        asn.MoveNextSibling();
        if (asn.Tag == 0xa0) {
            getAttributes(asn);
        }
        RawData = rawData;
    }
    void getVersion(Asn1Reader asn) {
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        Version = (Int32)(Asn1Utils.DecodeInteger(asn.GetTagRawData()) + 1);
    }
    void getSubject(Asn1Reader asn) {
        asn.MoveNextSiblingAndExpectTags(0x30);
        if (asn.PayloadLength != 0) {
            SubjectName = new X500DistinguishedName(asn.GetTagRawData());
        }
    }
    void getPublicKey(Asn1Reader asn) {
        asn.MoveNextSibling();
        PublicKey = PublicKeyExtensions.FromRawData(asn.GetTagRawData());
    }
    void getAttributes(Asn1Reader asn) {
        asn.MoveNext();
        if (asn.PayloadLength == 0) { return; }
        do {
            Pkcs9AttributeObject attribute = Pkcs9AttributeObjectFactory.CreateFromAsn1(asn.GetTagRawData());
            if (attribute.Oid.Value == X509ExtensionOid.CertificateExtensions) {
                //Extensions
                var extensions = new X509ExtensionCollection();
                extensions.Decode(attribute.RawData);
                foreach (X509Extension extension in extensions) {
                    InternalExtensions.Add(extension);
                }
            } else {
                InternalAttributes.Add(attribute);
            }
        } while (asn.MoveNextSibling());
    }

    /// <summary>
    /// Gets decoded textual representation (dump) of the current object.
    /// </summary>
    /// <returns>Textual representation of the current object.</returns>
    public virtual String Format() {
        var SB = new StringBuilder();
        var blob = new SignedContentBlob(RawData, ContentBlobType.SignedBlob);
        SB.Append(
            $@"PKCS10 Certificate Request:
Version: {Version}
Subject:
    {Subject ?? "EMPTY"}

{PublicKey.Format().TrimEnd()}
Request attributes (Count={InternalAttributes.Count}):{formatAttributes().TrimEnd()}
Request extensions (Count={InternalExtensions.Count}):{formatExtensions().TrimEnd()}
{blob.SignatureAlgorithm.ToString().TrimEnd()}    
Signature: Unused bits={blob.Signature.UnusedBits}
    {AsnFormatter.BinaryToString(blob.Signature.Value.ToArray(), EncodingType.HexAddress).Replace("\r\n", "\r\n    ")}
Signature matches Public Key: {SignatureIsValid}
");

        return SB.ToString();
    }
    String formatAttributes() {
        var sb = new StringBuilder();
        if (InternalAttributes.Count == 0) {
            return sb.ToString();
        }

        sb.AppendLine();
        for (Int32 index = 0; index < InternalAttributes.Count; index++) {
            Pkcs9AttributeObject attribute = InternalAttributes[index];
            sb.AppendLine(
                $"  Attribute[{index}], Length={attribute.RawData.Length} ({attribute.RawData.Length:x2}):");
            sb.AppendLine($"    {attribute.FormatEx(true).Replace("\r\n", "\r\n    ")}");
        }
        return sb.ToString();
    }
    String formatExtensions() {
        var sb = new StringBuilder();
        if (InternalExtensions.Count == 0) {
            return sb.ToString();
        }

        sb.AppendLine("");
        foreach (X509Extension extension in InternalExtensions) {
            sb.AppendLine($"    {extension.Oid.Format(true)}, Critial={extension.Critical}, Length={extension.RawData.Length:x2}:");
            sb.AppendLine($"        {extension.Format(true).Replace("\r\n", "\r\n        ")}");
        }
        return sb.ToString();
    }
}