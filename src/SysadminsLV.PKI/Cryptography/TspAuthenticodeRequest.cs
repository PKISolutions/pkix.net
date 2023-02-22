using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.Pkcs;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents Microsoft Authenticode Time-Stamp Request.
/// </summary>
public class TspAuthenticodeRequest : TspRequest {
    const String SPC_TIME_STAMP_REQUEST_OBJID = "1.3.6.1.4.1.311.3.2.1";
    const String PKCS_7_DATA                  = "1.2.840.113549.1.7.1";
    readonly Byte[] _data;

    /// <summary>
    /// Initializes a new instance of <strong>TspAuthenticodeRequest</strong> from existing signer information.
    /// </summary>
    /// <param name="signerInfo">Existing signer info object to use in the request.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>signerInfo</strong> parameter is null.
    /// </exception>
    public TspAuthenticodeRequest(PkcsSignerInfo signerInfo) : base(new Oid(SPC_TIME_STAMP_REQUEST_OBJID)) {
        if (signerInfo == null) {
            throw new ArgumentNullException(nameof(signerInfo));
        }
        _data = signerInfo.EncryptedHash;
    }

    /// <summary>
    /// Gets the data included in request. The value is a signature (<see cref="PkcsSignerInfo.EncryptedHash">EncryptedHash</see> property
    /// of <see cref="PkcsSignerInfo"/> object).
    /// </summary>
    public Byte[] Data => _data.ToArray();

    /// <summary>
    /// Initializes a new instance of <strong>TspAuthenticodeRequest</strong> from existing signer information.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    TspAuthenticodeRequest(Byte[] rawData) : base(new Oid(SPC_TIME_STAMP_REQUEST_OBJID)) {
        // TODO
    }

    /// <summary>
    /// Encodes request to RFC3161 request format.
    /// </summary>
    /// <returns>ASN.1-encoded byte array.</returns>
    public override Byte[] Encode() {
        var builder = Asn1Builder.Create()
            .AddObjectIdentifier(new Oid(SPC_TIME_STAMP_REQUEST_OBJID))
            .AddSequence(x => {
                             return x.AddObjectIdentifier(new Oid(PKCS_7_DATA))
                                 .AddExplicit(0, y => y.AddOctetString(_data));
                         });
        return builder.GetEncoded();
    }
    /// <inheritdoc />
    public override TspResponse SendRequest() {
        using var wc = new WebClient { Proxy = Proxy, Credentials = Credentials };
        PrepareWebClient(wc);
        String base64String = Encoding.ASCII.GetString(wc.UploadData(TsaUrl, "POST", Encode()));
        return new TspResponse(Convert.FromBase64String(base64String));
    }
}