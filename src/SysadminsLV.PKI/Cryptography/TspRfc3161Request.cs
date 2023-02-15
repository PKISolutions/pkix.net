using System;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents an <see href="https://tools.ietf.org/html/rfc3161">RFC 3161</see> Time-Stamp Protocol request message.
/// </summary>
public class TspRfc3161Request : TspRequest {
    const String RFC_3161_TIMESTAMP_REQUEST = "1.2.840.113549.1.9.16.1.4";
    readonly X509ExtensionCollection _extensions = new();
    Byte[] nonce;

    /// <summary>
    ///     Initializes a new instance of <strong>TspRequest</strong> from hash algorithm and data to hash.
    /// </summary>
    /// <param name="hashAlgorithm">
    ///     A hash algorithm to hash the data.
    /// </param>
    /// <param name="data">
    ///     Data to hash.
    /// </param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>hashAlgorithm</strong> or <strong>data</strong> is null.
    /// </exception>
    /// <exception cref="CryptographicException">
    ///     <strong>hashAlgorithm</strong> is invalid hashing algorithm.
    /// </exception>
    public TspRfc3161Request(Oid hashAlgorithm, Byte[] data) : base(new Oid(RFC_3161_TIMESTAMP_REQUEST)) {
        if (hashAlgorithm == null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }
        if (data == null) {
            throw new ArgumentNullException(nameof(data));
        }
        initialize(hashAlgorithm, data);
    }
    /// <summary>
    ///     Initializes a new instance of <strong>TspRequest</strong> from ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">
    ///     ASN.1-encoded byte array that represents an <see href="https://tools.ietf.org/html/rfc3161">RFC 3161</see> Time-Stamp
    ///     Protocol request message
    /// </param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>rawData</strong> parameter is null.
    /// </exception>
    public TspRfc3161Request(Byte[] rawData) : base(new Oid(RFC_3161_TIMESTAMP_REQUEST)) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        decode(new Asn1Reader(rawData));
    }

    /// <summary>
    /// Gets the version of TSP request. Currently, Version 1 is used.
    /// </summary>
    public Int32 Version { get; private set; } = 1;
    /// <summary>
    /// Gets the message to timestamp.
    /// </summary>
    public TspMessageImprint RequestMessage { get; private set; }
    /// <summary>
    /// Gets or sets the policy ID.
    /// </summary>
    public Oid PolicyID { get; set; }
    /// <summary>
    /// Gets or sets the nonce value supplied along with request.
    /// </summary>
    /// <remarks>
    /// Nonce is used by clients to verify the timeliness of the response when no local clock is available.
    /// <para>When presented, same nonce value must be returned by TSA server.</para>
    /// </remarks>
    public Boolean UseNonce { get; set; }
    /// <summary>
    /// Indicates whether the TSA's public key certificate that is referenced by the ESSCertID
    /// (<see href="https://tools.ietf.org/html/rfc2634">RFC 2634</see>) field inside a SigningCertificate attribute or by the ESSCertIDv2
    /// (<see href="https://tools.ietf.org/html/rfc5035">RFC 5035</see>) field inside a SigningCertificateV2 attribute in the response MUST be provided by the
    /// TSA in the certificates field from the SignedData structure in that response.
    /// </summary>
    public Boolean RequestCertificates { get; set; }
    /// <summary>
    /// Gets a collection of optional extensions associated with the current TSP request.
    /// </summary>
    public X509ExtensionCollection Extensions => _extensions.Duplicate();

    void initialize(Oid hashAlgorithm, Byte[] data) {
        RequestMessage = new TspMessageImprint(hashAlgorithm, data);
    }
    void decode(Asn1Reader asn) {
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        Version = (Int32)new Asn1Integer(asn).Value;
        asn.MoveNextAndExpectTags(48);
        RequestMessage = new TspMessageImprint(asn.GetTagRawData());
        while (asn.MoveNextSibling()) {
            switch (asn.Tag) {
                case (Byte)Asn1Type.OBJECT_IDENTIFIER:
                    PolicyID = new Asn1ObjectIdentifier(asn).Value;
                    break;
                case (Byte)Asn1Type.INTEGER:
                    UseNonce = true;
                    nonce = new Asn1Integer(asn).Value.ToByteArray();
                    break;
                case (Byte)Asn1Type.BOOLEAN:
                    RequestCertificates = new Asn1Boolean(asn).Value;
                    break;
                case 0xa0:
                    var extList = new X509ExtensionCollection();
                    extList.Decode(asn.GetTagRawData());
                    foreach (X509Extension extension in extList) {
                        _extensions.Add(extension);
                    }
                    break;
            }
        }
    }

    /// <inheritdoc />
    public override Byte[] Encode() {
        var builder = new Asn1Builder()
            .AddInteger(Version)
            .AddDerData(RequestMessage.Encode());
        if (PolicyID != null) {
            builder.AddObjectIdentifier(PolicyID);
        }
        if (UseNonce) {
            nonce = Guid.NewGuid().ToByteArray();
            builder.AddInteger(new BigInteger(nonce));
        } else {
            nonce = default;
        }
        if (RequestCertificates) {
            builder.AddBoolean(RequestCertificates);
        }
        if (_extensions.Count > 0) {
            builder.AddExplicit(0, Extensions.Encode(), false);
        }

        return builder.GetEncoded();
    }
    /// <summary>
    ///     Adds an optional extension to TSP request.
    /// </summary>
    /// <param name="extension">
    ///     Extension to add.
    /// </param>
    /// <returns>
    ///     <strong>True</strong> if extension was added to request, otherwise <strong>False</strong>.
    /// </returns>
    /// <remarks>
    ///     This method returns <strong>False</strong> when same extension is already added to the list.
    /// </remarks>
    public Boolean AddExtension(X509Extension extension) {
        if (extension == null) {
            throw new ArgumentNullException(nameof(extension));
        }
        if (_extensions.Cast<X509Extension>().Any(x => x.Oid.Value == extension.Oid.Value)) {
            return false;
        }
        _extensions.Add(extension);
        return true;
    }
    /// <summary>
    /// Gets the byte array associated with the nonce value. If nonce is not present, an empty array is returned.
    /// </summary>
    /// <returns>
    /// A 16-byte long random byte array if nonce is present or 0-byte long array if nonce is not present.
    /// </returns>
    /// <remarks>In the current implementation, random byte array is generated from random GUID instance.</remarks>
    public Byte[] GetNonceBytes() {
        return nonce == default
            ? Array.Empty<Byte>()
            : nonce.ToArray();
    }

    /// <inheritdoc />
    public override TspResponse SendRequest() {
        using var wc = new WebClient { Proxy = Proxy, Credentials = Credentials };
        PrepareWebClient(wc);
        return new TspResponse(wc.UploadData(TsaUrl, "POST", Encode()));
    }
}