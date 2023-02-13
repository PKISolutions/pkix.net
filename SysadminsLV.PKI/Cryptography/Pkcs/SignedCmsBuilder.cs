using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography.Pkcs;

/// <summary>
/// Contains properties and methods to construct and (optionally) sign PKCS#7/CMS message.
/// </summary>
public sealed class SignedCmsBuilder {
    const String SIGNED_CMS_TYPE  = "1.2.840.113549.1.7.2";
    const String COUNTER_SIGN     = "1.2.840.113549.1.9.6";
    const String RFC_COUNTER_SIGN = "1.3.6.1.4.1.311.3.3.1";
    const String TST_TOKEN_INFO   = "1.2.840.113549.1.9.16.1.4";
    const String CMC_DATA         = "1.3.6.1.5.5.7.12.2";
    const String PKCS_7_DATA      = "1.2.840.113549.1.7.1";
    readonly Oid _contentType;
    readonly Byte[] _content;

    /// <summary>
    ///     Initializes a new instance of <strong>SignedCmsBuilder</strong> from content type identifier and optional content.
    /// </summary>
    /// <param name="contentType">An object identifier that identifies the content type stored in PKCS#7 message.</param>
    /// <param name="content">
    ///     Content embedded in the PKCS#7 message. This parameter is optional.
    /// </param>
    /// <remarks>
    ///     If <strong>content</strong> parameter is null, signing operation will fail. Only message encoding is allowed.
    ///     <para>
    ///     If <strong>content</strong> parameter is presented, the content must be properly encoded without outer SEQUENCE type.
    ///     </para>
    /// </remarks>
    public SignedCmsBuilder(Oid contentType, Byte[] content = null) {
        _contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
        _content = content;
    }

    /// <summary>
    ///     Initializes a new instance of <strong>SignedCmsBuilder</strong> from existing Signed CMS. Data from existing CMS
    ///     is copied to builder and can be modified.
    /// </summary>
    /// <param name="cms">Existing Signed CMS message.</param>
    /// <exception cref="ArgumentNullException">
    ///     <srong>cms</srong> parameter is null.
    /// </exception>
    public SignedCmsBuilder(DefaultSignedPkcs7 cms) {
        if (cms == null) {
            throw new ArgumentNullException(nameof(cms));
        }

        _contentType = cms.ContentType;
        _content = cms.Content;
        DigestAlgorithms.AddRange(cms.DigestAlgorithms);
        Certificates.AddRange(cms.Certificates);
        RevocationLists.AddRange(cms.RevocationLists);
        SignerInfos.AddRange(cms.SignerInfos);
    }

    /// <summary>
    /// Gets the version of the CMS/PKCS#7 message. Currently, only version 1 is defined.
    /// </summary>
    public Int32 Version { get; } = 1;
    /// <summary>
    /// Gets the object identifier that identifies the content type stored in current object.
    /// </summary>
    public Oid ContentType => new(_contentType);
    /// <summary>
    /// Gets a collection of hashing algorithms.
    /// </summary>
    public AlgorithmIdentifierCollection DigestAlgorithms { get; } = new();
    /// <summary>
    /// Gets a collection of certificates contained in signed message.
    /// </summary>
    public X509Certificate2Collection Certificates { get; } = new();
    /// <summary>
    /// Gets an array of certificate revocation lists contained in the message.
    /// </summary>
    public X509CRL2Collection RevocationLists { get; } = new();
    /// <summary>
    /// Gets a collection of signer infos. This collection is read-only and populated automatically by signing current object.
    /// </summary>
    public PkcsSignerInfoCollection SignerInfos { get; } = new();

    Byte[] encodeSignedData() {
        Asn1Builder builder = Asn1Builder
            .Create()
            .AddInteger(Version)
            .AddDerData(DigestAlgorithms.Encode())
            .AddDerData(encodeContentInfo());
        // certificates
        if (Certificates.Count > 0) {
            builder.AddExplicit(0, Certificates.Encode(), false);
        }
        // CRLs
        if (RevocationLists.Count > 0) {
            var crlBytes = new List<Byte>();
            foreach (X509CRL2 crl in RevocationLists) {
                crlBytes.AddRange(crl.RawData);
            }
            builder.AddExplicit(1, crlBytes.ToArray(), false);
        }
        builder.AddDerData(SignerInfos.Encode());
        return builder.GetEncoded();
    }
    Byte[] encodeContentInfo() {
        Asn1Builder builder = Asn1Builder
            .Create()
            .AddObjectIdentifier(_contentType);
        if (_content != null) {
            switch (ContentType.Value) {
                case CMC_DATA: // CMC Data. For CMC: content [0] EXPLICIT OCTET STRING OPTIONAL
                    builder.AddExplicit(0, x => x.AddOctetString(_content));
                    break;
                default: // everything else. Suggested: content [0] EXPLICIT SEQUENCE OF ANY OPTIONAL
                    builder.AddExplicit(0, x => x.AddSequence(_content));
                    break;
            }
        }
        return builder.GetEncoded();
    }
    // we use this method to add signing certificates to Certificates collection.
    void addCerts(IEnumerable<X509Certificate2> signingCerts) {
        if (Certificates.Count == 0) {
            Certificates.AddRange(signingCerts.ToArray());
        } else {
            // we exclude possible certificate duplicates.
            foreach (X509Certificate2 signingCert in signingCerts) {
                Int32 index = Certificates.IndexOf(signingCert);
                if (index >= 0) {
                    Certificates.RemoveAt(index);
                }
                Certificates.Insert(0, signingCert);
            }
        }
    }
    Byte[] wrapEnvelope() {
        return Asn1Builder
            .Create()
            .AddObjectIdentifier(new Oid(SIGNED_CMS_TYPE))
            .AddExplicit(0, encodeSignedData(), true)
            .GetEncoded();
    }
        
    /// <summary>
    ///     Signs current PKCS#7 message and adds a new signer information to <see cref="SignerInfos"/> collection.
    ///     Certificates specified in <strong>chain</strong> parameter are added to <see cref="Certificates"/> collection.
    /// </summary>
    /// <param name="signer">signing object that contains public certificate, private key and signing configuration.</param>
    /// <param name="chain">
    ///     Signing certificate chain to add to CMS. This parameter is optional. If not specified, only leaf (signing) certificate
    ///     is added to <see cref="Certificates"/> collection and signed message.
    /// </param>
    /// <exception cref="InvalidOperationException">
    ///     No data to sign was passed in the constructor.
    /// </exception>
    /// <returns>
    ///     An instance of <see cref="DefaultSignedPkcs7"/> class that represents signed CMS message.
    /// </returns>
    /// <remarks>
    ///     You can call this method multiple times to attach multiple signatures to signed CMS message.
    /// </remarks>
    public DefaultSignedPkcs7 Sign(ICryptSigner signer, X509Certificate2Collection chain = null) {
        if (_content == null || _content.Length == 0) {
            throw new InvalidOperationException("There is no data to sign.");
        }
        var builder = new PkcsSignerInfoBuilder {
            ContentType = ContentType
        };
        SignerInfos.Add(builder.Sign(signer, _content));
        var certs = new List<X509Certificate2>(new[] { signer.SignerCertificate });
        if (chain != null) {
            certs.AddRange(chain.Cast<X509Certificate2>());
        }
        addCerts(certs);
        return new DefaultSignedPkcs7(wrapEnvelope());
    }
    /// <summary>
    /// Attaches a timestamp to signed CMS object.
    /// </summary>
    /// <param name="timestamp">TSP response returned from Time-Stamping Authority.</param>
    /// <param name="signerInfoIndex">Signature index to attach the timestamp.</param>
    /// <exception cref="NotSupportedException">
    /// Time-Stamp Response contains invalid content type.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     Data returned from Time-Stamping Authority does not contain valid response.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    ///     <strong>response</strong> parameter is null.
    /// </exception>
    /// <exception cref="IndexOutOfRangeException">
    ///     <strong>signerInfoIndex</strong> value exceeds the number of attached signatures.
    /// </exception>
    /// <remarks>Call <see cref="Encode"/> method to get timestamped object.</remarks>
    public void AddTimestamp(TspResponse timestamp, Int32 signerInfoIndex) {
        if (timestamp == null) {
            throw new ArgumentNullException(nameof(timestamp));
        }
        if (timestamp.Status.ResponseStatus != TspResponseStatus.Granted || timestamp.Status.ErrorCode != TspFailureStatus.None) {
            throw new ArgumentException("The time-stamp response is not successful.");
        }

        Pkcs9AttributeObject attribute;
        DefaultSignedPkcs7 tspCms = timestamp.GetSignedCms();
        switch (timestamp.ResponseType.Value) {
            case PKCS_7_DATA:
                // add timestamp signing certs to original CMS
                foreach (X509Certificate2 tspCert in tspCms.Certificates) {
                    if (!Certificates.Contains(tspCert)) {
                        Certificates.Add(tspCert);
                    }
                }
                // for Authenticode timestamp, we add SignerInfo from timestamp CMS
                var asn = new Asn1Reader(tspCms.SignerInfos.Encode());
                attribute = new Pkcs9AttributeObject(new Oid(COUNTER_SIGN), asn.GetPayload());
                break;
            case TST_TOKEN_INFO:
                attribute = new Pkcs9AttributeObject(new Oid(RFC_COUNTER_SIGN), tspCms.RawData);
                break;
            default: throw new NotSupportedException("Time-Stamp response contains invalid content type.");
        }
            
        var signerInfoBuilder = new PkcsSignerInfoBuilder(SignerInfos[signerInfoIndex]);
        Pkcs9AttributeObject attr = signerInfoBuilder.UnauthenticatedAttributes[COUNTER_SIGN];
        if (attr != null) {
            signerInfoBuilder.UnauthenticatedAttributes.Remove(attr);
        }
        attr = signerInfoBuilder.UnauthenticatedAttributes[RFC_COUNTER_SIGN];
        if (attr != null) {
            signerInfoBuilder.UnauthenticatedAttributes.Remove(attr);
        }
        signerInfoBuilder.AddUnauthenticatedAttribute(attribute);
        SignerInfos[signerInfoIndex] = signerInfoBuilder.Encode();
    }
    /// <summary>
    /// Encodes CMS without signing. 
    /// </summary>
    /// <returns>
    ///     An instance of <see cref="DefaultSignedPkcs7"/> class that represents signed CMS message.
    /// </returns>
    public DefaultSignedPkcs7 Encode() {
        return new DefaultSignedPkcs7(wrapEnvelope());
    }
}