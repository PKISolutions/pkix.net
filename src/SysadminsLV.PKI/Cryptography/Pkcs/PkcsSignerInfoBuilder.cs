using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography.Pkcs;

/// <summary>
/// This class is used to construct a <see cref="PkcsSignerInfo"/> object from input data.
/// </summary>
public sealed class PkcsSignerInfoBuilder {
    const String CONTENT_TYPE = "1.2.840.113549.1.9.3";
    const String MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

    readonly Pkcs9AttributeObjectCollection _authAttributes = new();
    readonly Pkcs9AttributeObjectCollection _unauthAttributes = new();
    AlgorithmIdentifier hashAlgId, pubKeyAlgId;
    PkcsSubjectIdentifier signerCert;
    Byte[] hashValue;

    /// <summary>
    /// Initializes a new instance of <strong>PkcsSignerInfoBuilder</strong> class.
    /// </summary>
    public PkcsSignerInfoBuilder() { }

    /// <summary>
    /// Initializes a new instance of <strong>PkcsSignerInfoBuilder</strong> class from existing signer information. All data from existing
    /// signer information is copied to builder.
    /// </summary>
    /// <param name="signerInfo">Existing signer information to copy the information from.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>signerInfo</strong> parameter is null.
    /// </exception>
    public PkcsSignerInfoBuilder(PkcsSignerInfo signerInfo) {
        if (signerInfo == null) {
            throw new ArgumentNullException(nameof(signerInfo));
        }

        initializeFromSignerInfo(signerInfo);
    }

    /// <summary>
    ///		Gets the signer information version. Default version Version 1.
    /// </summary>
    /// <remarks>
    ///		The version determines whether the message is a PKCS #7 message or a Cryptographic Message Syntax (CMS)
    ///		message. CMS is a newer superset of PKCS #7.
    /// </remarks>
    public Int32 Version { get; set; } = 1;
    /// <summary>
    ///     Gets or sets the subject identifier type used to identify the signer in signer info element. Default value is
    /// <strong>IssuerAndSerialNumber</strong>.
    /// </summary>
    public SubjectIdentifierType SubjectIdentifier { get; set; } = SubjectIdentifierType.IssuerAndSerialNumber;
    /// <summary>
    ///     Gets or sets the object identifier that identifies the content type.
    /// </summary>
    public Oid ContentType { get; set; }
    /// <summary>
    ///		Gets the <see cref="Pkcs9AttributeObjectCollection"/> collection of signed attributes that is associated with
    ///		the signer information. Signed attributes are signed along with the rest of the message content.
    /// </summary>
    public Pkcs9AttributeObjectCollection AuthenticatedAttributes => new(_authAttributes);
    /// <summary>
    ///		Gets the <see cref="Pkcs9AttributeObjectCollection"/> collection of unsigned attributes that is associated with
    ///		the <see cref="PkcsSignerInfo"/> content. Unsigned attributes can be modified without invalidating the
    ///		signature.
    /// </summary>
    public Pkcs9AttributeObjectCollection UnauthenticatedAttributes => new(_unauthAttributes);

    static void addUniqueAttribute(IList<Pkcs9AttributeObject> referenceList, Pkcs9AttributeObject attribute) {
        // if there is already same attribute (with same OID), remove old attribute and add new attribute
        // to avoid duplicates.
        for (Int32 index = 0; index < referenceList.Count; index++) {
            if (referenceList[index].Oid.Value == attribute.Oid.Value) {
                referenceList.RemoveAt(index);
                break;
            }
        }
        referenceList.Add(attribute);
    }

    void initializeFromSignerInfo(PkcsSignerInfo signerInfo) {
        Version = signerInfo.Version;
        SubjectIdentifier = signerInfo.Issuer.Type;
        signerCert = signerInfo.Issuer;
        Pkcs9AttributeObject attribute = signerInfo.AuthenticatedAttributes.FirstOrDefault(x => x.Oid.Value == CONTENT_TYPE);
        if (attribute != null) {
            ContentType = new Asn1ObjectIdentifier(attribute.RawData).Value;
        }
        pubKeyAlgId = signerInfo.EncryptedHashAlgorithm;
        hashAlgId = signerInfo.HashAlgorithm;
        hashValue = signerInfo.EncryptedHash;
        _authAttributes.AddRange(signerInfo.AuthenticatedAttributes);
    }

    void prepareSigning(Byte[] content) {
        addContentInfoAttribute();
        addMessageDigestAttribute(content);
    }
    void addContentInfoAttribute() {
        if (AuthenticatedAttributes[CONTENT_TYPE] == null) {
            AddAuthenticatedAttribute(new Pkcs9AttributeObject(new Oid(CONTENT_TYPE), new Asn1ObjectIdentifier(ContentType).GetRawData()));
        }
    }
    void addMessageDigestAttribute(Byte[] content) {
        if (_authAttributes.All(x => x.Oid.Value != MESSAGE_DIGEST)) {
            using var hasher = HashAlgorithm.Create(new Oid(hashAlgId.AlgorithmId.Value).FriendlyName);
            if (hasher == null) {
                throw new ArgumentException("Specified hash algorithm is not valid hashing algorithm");
            }
            var attrValue = Asn1Utils.Encode(hasher.ComputeHash(content), (Byte)Asn1Type.OCTET_STRING);
            AddAuthenticatedAttribute(new Pkcs9AttributeObject(new Oid(MESSAGE_DIGEST), attrValue));
        }
    }
    void signContent(ICryptSigner messageSigner, Byte[] content) {
        hashAlgId = new AlgorithmIdentifier(messageSigner.HashingAlgorithm, Array.Empty<Byte>());
        pubKeyAlgId = new AlgorithmIdentifier(messageSigner.PublicKeyAlgorithm, Array.Empty<Byte>());
        prepareSigning(content);
        SignedContentBlob signedBlob;
        if (_authAttributes.Any()) {
            // auth attributes are encoded as IMPLICIT (OPTIONAL), but RFC2315 §9.3 requires signature computation for SET
            var attrBytes = _authAttributes.Encode();
            attrBytes[0] = 0x31;
            signedBlob = new SignedContentBlob(attrBytes, ContentBlobType.ToBeSignedBlob);
        } else {
            if (content == null) {
                throw new ArgumentException("'content' parameter cannot be null if no authenticated attributes present.");
            }
            signedBlob = new SignedContentBlob(content, ContentBlobType.ToBeSignedBlob);
        }
        signerCert = new PkcsSubjectIdentifier(messageSigner.SignerCertificate, SubjectIdentifier);
        signedBlob.Sign(messageSigner);
        hashValue = signedBlob.Signature.Value;
    }

    /// <summary>
    /// Adds authenticated attribute. Authenticated attribute will be protected from tampering by digitally signing its contents.
    /// </summary>
    /// <param name="attribute">
    /// An attribute that must be protected by digital signature.
    /// </param>
    /// <remarks>
    /// If same attribute (with same object identifier) is already presented in collection, it will be overwritten with attribute in the
    /// <strong>attribute</strong> parameter.
    /// </remarks>
    public void AddAuthenticatedAttribute(Pkcs9AttributeObject attribute) {
        if (attribute == null) {
            throw new ArgumentNullException(nameof(attribute));
        }
        addUniqueAttribute(_authAttributes, attribute);
    }
    /// <summary>
    /// Adds unauthenticated attribute. Unlike authenticated attribute, unauthenticated attributes are not protected by signer's signature.
    /// Unauthenticated attributes are replaceable. Such attributes are counter-signing and timestamp. These attributes are informative or
    /// provide their own integrity mechanisms.
    /// </summary>
    /// <param name="attribute">
    /// An attribute that must be protected by digital signature.
    /// </param>
    /// <remarks>
    /// If same attribute (with same object identifier) is already presented in collection, it will be overwritten with attribute in the
    /// <strong>attribute</strong> parameter.
    /// </remarks>
    public void AddUnauthenticatedAttribute(Pkcs9AttributeObject attribute) {
        if (attribute == null) {
            throw new ArgumentNullException(nameof(attribute));
        }
        addUniqueAttribute(_unauthAttributes, attribute);
    }

    /// <summary>
    ///     Encodes and signs the content using the signer object used in 
    /// </summary>
    /// <returns>
    ///     An instance of <see cref="PkcsSignerInfo"/> class.
    /// </returns>
    /// <remarks>
    ///     Before signing, the method adds two authenticated attributes: content type and message digest. Authenticated attributes are then
    ///     signed with signer's private key.
    /// </remarks>
    public PkcsSignerInfo Encode() {
        if (_authAttributes.All(x => x.Oid.Value != MESSAGE_DIGEST)) {
            throw new InvalidOperationException();
        }
        // version
        Asn1Builder builder = Asn1Builder.Create().AddInteger(Version);
        // signerIdentifier
        builder.AddDerData(signerCert.Encode());
        // digestAlgorithm
        builder.AddDerData(hashAlgId.RawData);
        // authenticatedAttributes
        if (_authAttributes.Any()) {
            builder.AddExplicit(0, _authAttributes.Encode(), false);
        }
        // digestEncryptionAlgorithm
        builder.AddDerData(pubKeyAlgId.RawData);
        // encryptedDigest
        builder.AddOctetString(hashValue);
        // unauthenticatedAttributes
        if (_unauthAttributes.Any()) {
            builder.AddExplicit(1, UnauthenticatedAttributes.Encode(), false);
        }

        // wrap
        return new PkcsSignerInfo(builder.GetEncoded());
    }
    /// <summary>
    /// Signs authenticated attributes.
    /// </summary>
    /// <param name="messageSigner">
    /// Signer certificate to use in signing operations.
    /// </param>
    /// <param name="content">
    /// An optional content to sign. This parameter can be null if <see cref="AuthenticatedAttributes"/> contain <strong>Message Digest</strong>
    /// attribute. If this attribute is not presented, content parameter cannot be null.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <strong>messageSigner</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <strong>Message Digest</strong> attribute is missing and no content provided to sign.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// Signer certificate is configured to use PSS padding for signature which is not supported.
    /// </exception>
    /// <returns>Signed signer info that can be added to signed CMS message.</returns>
    public PkcsSignerInfo Sign(ICryptSigner messageSigner, Byte[] content) {
        if (messageSigner == null) {
            throw new ArgumentNullException(nameof(messageSigner));
        }
        if (_authAttributes.Any() && content == null) {
            throw new ArgumentException("'content' parameter cannot be null if no authenticated attributes present.");
        }
        if (messageSigner.PaddingScheme == RSASignaturePadding.Pss) {
            throw new CryptographicException("PSS padding scheme is not supported.");
        }
        signContent(messageSigner, content);
        return Encode();
    }
}