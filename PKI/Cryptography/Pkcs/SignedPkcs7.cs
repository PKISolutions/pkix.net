using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Tools.MessageOperations;

namespace SysadminsLV.PKI.Cryptography.Pkcs;

/*
RFC2315 https://tools.ietf.org/html/rfc2315
SignedData ::= SEQUENCE {
    version             Version,
    digestAlgorithms    DigestAlgorithmIdentifiers,
    contentInfo         ContentInfo,
    certificates [0]    IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
    crls         [1]    IMPLICIT CertificateRevocationLists OPTIONAL,
    signerInfos         SignerInfos
}
*/
/// <summary>
/// Represents base class for any sort of PKCS #7 signed message.
/// </summary>
/// <typeparam name="T">Any reference type that represents the contents of signed message.</typeparam>
/// <remarks>This class is <strong>abstract</strong> and cannot be instantiated.</remarks>
public abstract class SignedPkcs7<T> where T : class {
    const String MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    readonly List<AlgorithmIdentifier> _digestAlgorithms = new();
    readonly IList<X509Certificate2> _certificates = new List<X509Certificate2>();
    readonly List<X509CRL2> _crls = new();
    readonly PkcsSignerInfoCollection _signerInfos = new();
    readonly List<Byte> _rawData = new();

    Int32 contentOffset;
    Int32 contentSize;

    /// <summary>
    /// Initializes a new instance of <strong>SignedPkcs7</strong> message from ASN.1-encoded PKCS# signed message.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array that represent PKCS# signed message</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>rawData</strong> parameter is null.
    /// </exception>
    protected SignedPkcs7(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        DecodeCms(new Asn1Reader(rawData));
    }

    /// <summary>
    /// Gets the version of the CMS/PKCS#7 message. Currently, only version 1 is defined.
    /// </summary>
    public Int32 Version { get; private set; }
    /// <summary>
    /// Gets the object identifier that identifies the content type stored in <see cref="Content"/> member.
    /// </summary>
    public Oid ContentType { get; private set; }
    /// <summary>
    /// Gets the content of the current signed message. Object type is determined by implementer based on
    /// <see cref="ContentType"/> information.
    /// </summary>
    public T Content { get; protected set; }
    /// <summary>
    /// Gets a collection of hashing algorithms.
    /// </summary>
    public AlgorithmIdentifierCollection DigestAlgorithms => new(_digestAlgorithms);
    /// <summary>
    /// Gets a collection of certificates contained in signed message.
    /// </summary>
    public X509Certificate2Collection Certificates => new(_certificates.ToArray());
    /// <summary>
    /// Gets an array of certificate revocation lists contained in the message.
    /// </summary>
    public X509CRL2Collection RevocationLists => new(_crls.ToArray());
    /// <summary>
    /// Gets an array of signer information that were used to sign the message.
    /// </summary>
    public PkcsSignerInfoCollection SignerInfos => new(_signerInfos);
    /// <summary>
    /// Gets the ASN.1-encoded byte array that represents current object.
    /// </summary>
    public Byte[] RawData => _rawData.ToArray();

    /// <summary>
    /// Decodes cms from ASN reader.
    /// </summary>
    /// <param name="asn">An instance of ASN.1 reader that contains signed PKCS#7 data.</param>
    protected void DecodeCms(Asn1Reader asn) {
        reset();
        asn.MoveNext();
        ContentType = new Asn1ObjectIdentifier(asn).Value;
        asn.MoveNextAndExpectTags(0xa0); // [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL, 0xa0
        asn.MoveNextAndExpectTags(0x30); // SEQUENCE OF ANY
        asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER); // version
        Version = (Int32)new Asn1Integer(asn).Value;
        asn.MoveNextSiblingAndExpectTags(0x31);
        decodeDigestAlgorithms(asn);
        asn.MoveNextSiblingAndExpectTags(0x30); // ContentInfo
        Byte[] content = extractContent(asn);
        while (asn.MoveNextSibling()) {
            switch (asn.Tag) {
                case 0xa0:
                    decodeCertificates(asn);
                    break;
                case 0xa1:
                    decodeCRLs(asn);
                    break;
                case 0x31:
                    decodeSignerInfos(asn);
                    break;
                default:
                    throw new ArgumentException("Invalid type.");
            }
        }
        _rawData.AddRange(asn.GetRawData());
        DecodeContent(content);
    }
    void reset() {
        _rawData.Clear();
        _digestAlgorithms.Clear();
        _certificates.Clear();
        _crls.Clear();
        _signerInfos.Clear();
    }
    void decodeDigestAlgorithms(Asn1Reader asn) {
        // asn tag -> SET (0x31)
        Int32 offset = asn.Offset;
        if (asn.PayloadLength == 0) { return; }
        asn.MoveNext();
        do {
            _digestAlgorithms.Add(new AlgorithmIdentifier(asn.GetTagRawData()));
        } while (asn.MoveNextSibling());

        asn.Seek(offset);
    }
    Byte[] extractContent(Asn1Reader asn) {
        Int32 offset = asn.Offset;
        asn.MoveNext();
        Byte[] payload = null;
        ContentType = new Asn1ObjectIdentifier(asn.GetTagRawData()).Value;
        if (asn.MoveNextSibling()) {
            // content [0] EXPLICIT ANY DEFINED BY contentType
            asn.MoveNextAndExpectTags((Byte)Asn1Type.OCTET_STRING, 48); // octet string or sequence
            payload = asn.GetPayload();
            contentOffset = asn.Offset;
            contentSize = asn.TagLength;
        }
        asn.Seek(offset);
        return payload;
    }
    void decodeCertificates(Asn1Reader asn) {
        if (asn.PayloadLength == 0) { return; }
        Int32 offset = asn.Offset;
        asn.MoveNext();
        do {
            // sometimes we can get thing called ExtendedCertificate. I have no idea what it is.
            try {
                _certificates.Add(new X509Certificate2(asn.GetTagRawData()));
            } catch { }
        } while (asn.MoveNextSibling());
        asn.Seek(offset);
    }
    void decodeCRLs(Asn1Reader asn) {
        if (asn.PayloadLength == 0) { return; }
        Int32 offset = asn.Offset;
        asn.MoveNext();
        do {
            _crls.Add(new X509CRL2(asn.GetTagRawData()));
        } while (asn.MoveNextSibling());
        asn.Seek(offset);
    }
    void decodeSignerInfos(Asn1Reader asn) {
        if (asn.PayloadLength == 0) { return; }
        Int32 offset = asn.Offset;
        asn.MoveNext();
        do {
            _signerInfos.Add(new PkcsSignerInfo(asn.GetTagRawData()));
        } while (asn.MoveNextSibling());
        asn.Seek(offset);
    }

    Byte[] calculateHash(Oid hashOid) {
        if (contentSize == 0) {
            return null;
        }
        var asn = new Asn1Reader(_rawData.Skip(contentOffset).Take(contentSize).ToArray());
        using var hasher = HashAlgorithm.Create(hashOid.FriendlyName);
        return hasher?.ComputeHash(asn.GetPayload());
    }
    Byte[] getHashValue(PkcsSignerInfo signerInfo) {
        X509Attribute attr = signerInfo.AuthenticatedAttributes[MESSAGE_DIGEST];
        if (attr == null) {
            return null;
        }
        var asn = new Asn1Reader(attr.RawData);
        return asn.GetPayload();
    }
    Boolean compareHashes(ICollection<Byte> first, ICollection<Byte> second) {
        if (first.Count != second.Count) {
            return false;
        }
        return first.Intersect(second).Count() == first.Count;
    }
    Boolean checkSingleHash(PkcsSignerInfo signerInfo) {
        Byte[] hashValue = getHashValue(signerInfo);
        if (hashValue == null) {
            return false;
        }
        Byte[] hash = calculateHash(signerInfo.HashAlgorithm.AlgorithmId);
        return compareHashes(hashValue, hash);
    }
    Boolean checkSingleSignature(PkcsSignerInfo signerInfo, Boolean validOnly) {
        X509Certificate2Collection certs;
        X509Certificate2 signerCert = null;

        switch (signerInfo.Issuer.Type) {
            case SubjectIdentifierType.IssuerAndSerialNumber:
                var issuerAndSerial = (X509IssuerSerial)signerInfo.Issuer.Value;
                certs = Certificates.Find(X509FindType.FindBySerialNumber, issuerAndSerial.SerialNumber, validOnly);
                certs = certs.Find(X509FindType.FindByIssuerDistinguishedName, issuerAndSerial.Issuer, validOnly);
                if (certs.Count > 0) {
                    signerCert = certs[0];
                }
                break;
            case SubjectIdentifierType.SubjectKeyIdentifier:
                String si = signerInfo.Issuer.Value.ToString();
                certs = Certificates.Find(X509FindType.FindBySubjectKeyIdentifier, si, true);
                if (certs.Count > 0) {
                    signerCert = certs[0];
                }
                break;
            case SubjectIdentifierType.NoSignature:
                return checkSingleHash(signerInfo);
            default:
                throw new ArgumentOutOfRangeException();
        }
        // return False if we can't find signer certificate.
        if (signerCert == null) {
            return false;
        }

        // if hash check passed, do hash signature validation.
        var signer = new MessageSigner(signerCert, new Oid2(signerInfo.HashAlgorithm.AlgorithmId, false));
        Byte[] data = signerInfo.AuthenticatedAttributes.Encode();
        data[0] = 0x31;
        if (validOnly) {
            return signer.VerifyData(data, signerInfo.EncryptedHash) && checkCertChain(signerCert);
        }
        return signer.VerifyData(data, signerInfo.EncryptedHash);
    }
    Boolean checkCertChain(X509Certificate2 cert) {
        var chain = new X509Chain();
        chain.ChainPolicy.ExtraStore.AddRange(Certificates);
        return chain.Build(cert);
    }

    /// <summary>
    /// Verifies the data integrity of the CMS/PKCS #7 message. This is a specialized method used in specific security infrastructure applications
    /// that only wish to check the hash of the CMS message, rather than perform a full digital signature verification.
    /// </summary>
    /// <param name="checkAll">
    ///     Specifies if all hashes are checked when multiple signatures are used. This parameter has no meaning when only one signature is attached.
    /// </param>
    /// <returns>
    ///     <strong>True</strong> if hash stored in signer information matches content hash, otherwise <strong>False</strong>.
    /// </returns>
    /// <remarks>
    ///     When message is signed with single signer, its hash is compared with actual hash of the message.
    ///     <para>
    ///     When message is signed by multiple signers and <strong>checkAll</strong> is set to <strong>false</strong>,
    ///     then method returns <strong>True</strong> if hash check passed for at least one signer.
    ///     </para>
    ///     <para>
    ///     When message is signed by multiple signers and <strong>checkAll</strong> is set to <strong>true</strong>,
    ///     then method returns <strong>True</strong> if hash check passed for all signers. If hash check fails for at least one signer, or
    ///     any signer has absent hash value to compare with, the method will return <strong>false</strong>.
    ///     </para>
    /// </remarks>
    public Boolean CheckHash(Boolean checkAll) {
        if (_signerInfos.Count == 0) {
            return false;
        }
        return checkAll
            ? _signerInfos.All(checkSingleHash)
            : _signerInfos.Any(checkSingleHash);
    }
    /// <summary>
    /// Checks the signature of the CMS/PKCS #7 message and, optionally, validates the signers' certificates.
    /// </summary>
    /// <param name="checkSignatureOnly">
    /// checks the signature 
    /// </param>
    /// <param name="checkAll"></param>
    /// <returns></returns>
    /// <remarks>
    ///     When message is signed with single signer, its signature is verified.
    ///     <para>
    ///     When message is signed by multiple signers and <strong>checkAll</strong> is set to <strong>false</strong>,
    ///     then method returns <strong>True</strong> if signature check passed for at least one signer.
    ///     </para>
    ///     <para>
    ///     When message is signed by multiple signers and <strong>checkAll</strong> is set to <strong>true</strong>,
    ///     then method returns <strong>True</strong> if signature check passed for all signers. If signature check fails for at least
    ///     one signer, or any signer has absent signature value to validate, the method will return <strong>false</strong>.
    ///     </para>
    /// </remarks>
    public Boolean CheckSignature(Boolean checkSignatureOnly, Boolean checkAll) {
        if (_signerInfos.Count == 0) {
            return false;
        }
        return checkAll
            ? _signerInfos.All(x => checkSingleSignature(x, !checkSignatureOnly))
            : _signerInfos.Any(x => checkSingleSignature(x, !checkSignatureOnly));
    }
    /// <summary>
    /// Returns an instance of <see cref="SignedCms"/> provided by .NET Framework.
    /// </summary>
    /// <returns>an instance of <see cref="SignedCms"/> that represents current object.</returns>
    public SignedCms GetSignedCms() {
        var cms = new SignedCms();
        cms.Decode(_rawData.ToArray());
        return cms;
    }
    /// <summary>
    /// Implementers use this method to decode content of the signed message and set it in
    /// <see cref="Content"/> member.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded array that represents signed message's content. Can be null.</param>
    /// <remarks> This method is invoked after entire PKCS #7 structure is decoded.</remarks>
    protected abstract void DecodeContent(Byte[] rawData);
}