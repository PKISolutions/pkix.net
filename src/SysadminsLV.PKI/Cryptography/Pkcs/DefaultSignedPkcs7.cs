using System;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.Pkcs;

/// <summary>
/// Represents general/common implementation of signed PKCS #7 with arbitrary content type. The type of
/// <see cref="SignedPkcs7{T}.Content">Content</see> is <strong>Byte[]</strong>.
/// </summary>
public sealed class DefaultSignedPkcs7 : SignedPkcs7<Byte[]> {
    /// <inheritdoc />
    public DefaultSignedPkcs7(Byte[] rawData) : base(rawData) { }
    /// <inheritdoc />
    protected override void DecodeContent(Byte[] rawData) {
        Content = rawData;
    }

    void addTimestamp(TspResponse response) {
        var builder = new SignedCmsBuilder(this);
        builder.AddTimestamp(response, 0);
        DecodeCms(new Asn1Reader(builder.Encode().RawData));
    }

    /// <summary>
    /// Timestamps the specified signature using external Time-Stamp Authority.
    /// </summary>
    /// <param name="tsaUrl">
    ///     An URL to a Time-Stamp Authority.
    /// </param>
    /// <param name="hashAlgorithm">
    ///     Hash algorithm to use by TSA to sign response.
    /// </param>
    /// <param name="signerInfoIndex">
    ///     A zero-based index of signature to timestamp. Default value is 0.
    /// </param>
    /// <remarks>This method adds an RFC3161 Counter Signature.</remarks>
    public void AddTimestamp(String tsaUrl, Oid hashAlgorithm, Int32 signerInfoIndex = 0) {
        var tspReq = new TspRfc3161Request(hashAlgorithm, SignerInfos[signerInfoIndex].EncryptedHash) {
                         TsaUrl = new Uri(tsaUrl)
                     };
        TspResponse response = tspReq.SendRequest();

        addTimestamp(response);
    }
    /// <summary>
    /// Adds a pre-created timestamp to the signature.
    /// </summary>
    /// <param name="response">A response object from Time-Stamp Authority.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>response</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     <strong>response</strong> object does not contain valid timestamp token.
    /// </exception>
    /// <remarks>
    ///     This method does not validate if hash value in signed timestamp matches the current object.
    /// </remarks>
    public void AddTimestamp(TspResponse response) {
        if (response == null) {
            throw new ArgumentNullException(nameof(response));
        }
        if (response.Status.ResponseStatus != TspResponseStatus.Granted) {
            throw new ArgumentException("Response object is not successful.");
        }

        addTimestamp(response);
    }
}