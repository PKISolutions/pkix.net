using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents Authority Key Identifier extension. The authority key identifier extension provides a means of
/// identifying the public key corresponding to the private key used to sign a certificate.
/// </summary>
public sealed class X509AuthorityKeyIdentifierExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.AuthorityKeyIdentifier);

    /// <summary>
    /// Initializes a new instance of <strong>X509AuthorityKeyIdentifierExtension</strong> class from
    /// ASN.1-encoded AKI extension value and a value that identifies whether the extension is critical.
    /// </summary>
    /// <param name="aki">An ASN.1-encoded Authority Key Identifier extension value.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    /// <exception cref="System.ArgumentNullException">
    /// <strong>aki</strong> parameter is null;
    /// </exception>
    public X509AuthorityKeyIdentifierExtension(AsnEncodedData aki, Boolean critical)
        : base(_oid, aki.RawData, critical) {
        if (aki == null) {
            throw new ArgumentNullException(nameof(aki));
        }
        m_decode(aki.RawData);
    }
    /// <summary>
    /// Initializes a new instance of <strong>X509AuthorityKeyIdentifierExtension</strong> class from
    /// a key identifier value and a value that identifies whether the extension is critical.
    /// </summary>
    /// <param name="keyIdentifier">Must be a hex string that represents hash value.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    /// <exception cref="System.ArgumentNullException">
    /// <strong>keyIdentifier</strong> value is null or empty.
    /// </exception>
    public X509AuthorityKeyIdentifierExtension(String keyIdentifier, Boolean critical) {
        if (String.IsNullOrEmpty(keyIdentifier)) {
            throw new ArgumentNullException(nameof(keyIdentifier));
        }
        initializeFromKeyId(keyIdentifier, critical);
    }
    /// <summary>
    /// Initializes a new instance of <strong>X509AuthorityKeyIdentifierExtension</strong> class from
    /// an issuer certificate, extension generation flags an a value that identifies whether the extension
    /// is critical.
    /// </summary>
    /// <param name="issuer">Issuer certificate which is used to construct the AKI extension.</param>
    /// <param name="type">
    /// Indicates which issuer components are included in the AKI extension. If the value is zero (None),
    /// then default <strong>KeyIdentifier</strong> component will be included.
    /// </param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    /// <exception cref="System.ArgumentNullException">
    /// <strong>issuer</strong> parameter is null.
    /// </exception>
    /// <remarks>
    /// If <strong>flags</strong> parameter contains <strong>AlternativeNames</strong> and issuer certificate
    /// does not contain Subject Alternative Names (SAN) extension, <strong>AlternativeNames</strong> flags
    /// is ignored. If <strong>AlternativeNames</strong> is the only flag, and SAN extension is missing, only
    /// <strong>KeyIdentifier</strong> component will be included.
    /// </remarks>
    public X509AuthorityKeyIdentifierExtension(X509Certificate2 issuer, AuthorityKeyIdentifierType type, Boolean critical) {
        if (issuer == null || IntPtr.Zero.Equals(issuer.Handle)) {
            throw new ArgumentNullException(nameof(issuer));
        }
        if (type == AuthorityKeyIdentifierType.AlternativeNames && issuer.Extensions[X509ExtensionOid.SubjectAlternativeNames] == null) {
            type = AuthorityKeyIdentifierType.KeyIdentifier;
        }
        if (type == AuthorityKeyIdentifierType.None) {
            type |= AuthorityKeyIdentifierType.KeyIdentifier;
        }
        initializeFromCert(issuer, type, critical);
    }

    /// <summary>
    /// Indicates which components are included in the Authority Key Identifier extension.
    /// </summary>
    public AuthorityKeyIdentifierType IncludedComponents { get; private set; }
    /// <summary>
    /// Gets an octet string of the KeyIdentifier component. May be null.
    /// </summary>
    public String KeyIdentifier { get; private set; }
    /// <summary>
    /// Gets a collection of issuer alternative names. May be null.
    /// </summary>
    public X509AlternativeNameCollection IssuerNames { get; private set; }
    /// <summary>
    /// Gets the serial number of the issuer certificate. May be null.
    /// </summary>
    public String SerialNumber { get; private set; }

    void initializeFromCert(X509Certificate2 issuer, AuthorityKeyIdentifierType type, Boolean critical) {
        Oid = _oid;
        Critical = critical;
        IncludedComponents = AuthorityKeyIdentifierType.None;
        var rawData = new List<Byte>();
        if ((type & AuthorityKeyIdentifierType.KeyIdentifier) > 0) {
            using (var hasher = SHA1.Create()) {
                Byte[] hashBytes = hasher.ComputeHash(issuer.PublicKey.EncodedKeyValue.RawData);
                KeyIdentifier = AsnFormatter.BinaryToString(hashBytes, EncodingType.HexRaw, EncodingFormat.NOCRLF);
                rawData.AddRange(Asn1Utils.Encode(hashBytes, 0x80));
            }
            IncludedComponents |= AuthorityKeyIdentifierType.KeyIdentifier;
        }
        if ((type & AuthorityKeyIdentifierType.AlternativeNames) > 0) {
            X509Extension san = issuer.Extensions[X509ExtensionOid.SubjectAlternativeNames];
            if (san == null) {
                throw new ArgumentException("Reference certificate doesn't contain subject alternative names extension.");
            }
            var encoded = new AsnEncodedData(san.RawData);
            var sanExt = new X509SubjectAlternativeNamesExtension(encoded, false);
            IssuerNames = sanExt.AlternativeNames;
            var asn = new Asn1Reader(san.RawData);
            rawData.AddRange(Asn1Utils.Encode(asn.GetPayload(), 0x81));
            IncludedComponents |= AuthorityKeyIdentifierType.AlternativeNames;
        }
        if ((type & AuthorityKeyIdentifierType.SerialNumber) > 0) {
            SerialNumber = issuer.SerialNumber;
            rawData.AddRange(Asn1Utils.Encode(issuer.GetSerialNumber().Reverse().ToArray(), 0x82));
            IncludedComponents |= AuthorityKeyIdentifierType.SerialNumber;
        }
        RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    void initializeFromKeyId(String keyId, Boolean critical) {
        Oid = _oid;
        Critical = critical;
        IncludedComponents = AuthorityKeyIdentifierType.KeyIdentifier;

        Byte[] keyIdBytes = AsnFormatter.StringToBinary(keyId);
        KeyIdentifier = AsnFormatter.BinaryToString(keyIdBytes, EncodingType.HexRaw, EncodingFormat.NOCRLF);
        RawData = Asn1Utils.Encode(AsnFormatter.StringToBinary(keyId, EncodingType.Hex), 0x80);
        RawData = Asn1Utils.Encode(RawData, 48);
    }
    void m_decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
        asn.MoveNext();
        IncludedComponents = AuthorityKeyIdentifierType.None;
        do {
            switch (asn.Tag) {
                case 0x80:
                    KeyIdentifier = AsnFormatter.BinaryToString(asn.GetPayload(), EncodingType.HexRaw, EncodingFormat.NOCRLF);
                    IncludedComponents |= AuthorityKeyIdentifierType.KeyIdentifier;
                    break;
                case 0xa1:
                    IssuerNames = new X509AlternativeNameCollection();
                    Byte[] bytes = Asn1Utils.Encode(asn.GetPayload(), 48);
                    IssuerNames.Decode(bytes);
                    IncludedComponents |= AuthorityKeyIdentifierType.AlternativeNames;
                    break;
                case 0x82:
                    SerialNumber = AsnFormatter.BinaryToString(asn.GetPayload());
                    IncludedComponents |= AuthorityKeyIdentifierType.SerialNumber;
                    break;
            }
        } while (asn.MoveNextSibling());
    }
}