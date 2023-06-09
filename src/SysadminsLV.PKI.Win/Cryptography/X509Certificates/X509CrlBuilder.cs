using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents X.509 certificate revocation list (CRL) generator class.
/// </summary>
public class X509CrlBuilder {
    readonly List<X509Extension> _extensions = new();

    /// <summary>
    /// Initializes a new instance of <strong>X509CrlBuilder</strong> with no CRL information.
    /// </summary>
    public X509CrlBuilder() { }
    /// <summary>
    /// Initializes a new instance of <strong>X509CrlBuilder</strong> from existing CRL data.
    /// </summary>
    /// <param name="existingCrl">Existing CRL object.</param>
    /// <remarks>Only version, extensions and a list of revoked certificates are copied to the builder.</remarks>
    public X509CrlBuilder(X509CRL2 existingCrl) {
        Version = existingCrl.Version;
        _extensions.AddRange(
            existingCrl.Extensions
                .Cast<X509Extension>()
                // we do not add NextCrlPublish extension.
                .Where(x => x.Oid.Value != X509ExtensionOid.NextCRLPublish));
        RevokedCertificates.AddRange(existingCrl.RevokedCertificates);
    }

    /// <summary>
    /// Gets or sets the version of the CRL. Valid values are 1 and 2. If <see cref="Extensions"/> member
    /// contains at least one element, CRL version is automatically set to 2.
    /// </summary>
    public Int32 Version { get; set; }
    /// <summary>
    /// Gets or sets start date for CRL. Default value is current date and time.
    /// </summary>
    public DateTime ThisUpdate { get; set; } = DateTime.Now;
    /// <summary>
    /// Gets or sets CRL expiration date. If not set, or expiration date is set to date before
    /// <see cref="ThisUpdate"/>, expiration date is set 7 days after CRL's start date.
    /// </summary>
    public DateTime? NextUpdate { get; set; } = DateTime.Now.AddDays(7);
    /// <summary>
    /// Gets or sets the local date and time at which new CRL is expected to be published by CA.
    /// Normally this value is either, equals to <see cref="NextUpdate"/> or a bit smaller. But this
    /// value must be within CRL validity.
    /// </summary>
    public DateTime? NextCrlPublish { get; set; }
    /// <summary>
    /// Gets or sets the increment value for CRL Number extension. If value is zero or negative, current CRL Number
    /// value is used. If existing CRL doesn't contain CRL Number extension, this value is ignored. 
    /// </summary>
    public UInt32 CrlNumberIncrement { get; set; } = 0;
    /// <summary>
    /// Gets extensions to be added to CRL.
    /// </summary>
    public X509ExtensionCollection Extensions {
        get {
            var extensions = new X509ExtensionCollection();
            extensions.AddRange(_extensions);
            return extensions;
        }
    }
    /// <summary>
    /// Gets or adds a list of revoked certificates contained in CRL.
    /// </summary>
    public X509CRLEntryCollection RevokedCertificates { get; } = new();
    /// <summary>
    /// Gets or sets hashing algorithm to use during encoding. If not set, default value 'SHA256' is set.
    /// </summary>
    public Oid HashingAlgorithm { get; set; } = new(AlgorithmOid.SHA256);

    void generateExtensions(X509Certificate2 issuer) {
        processAkiExtension(issuer);
        processCAVersionExtension(issuer);
        processNextCrlPublishExtension();
        processCrlNumberExtension();
    }
    void processAkiExtension(X509Certificate2 issuer) {
        // remove AKI extension from existing extensions
        GenericArray.RemoveExtension(_extensions, X509ExtensionOid.AuthorityKeyIdentifier);
        // generate AKI from issuer certificate
        _extensions.Add(new X509AuthorityKeyIdentifierExtension(issuer, AuthorityKeyIdentifierType.KeyIdentifier, false));
    }
    void processCAVersionExtension(X509Certificate2 issuer) {
        // remove CA Version extension from existing extensions
        GenericArray.RemoveExtension(_extensions, X509ExtensionOid.CAVersion);
        X509Extension e = issuer.Extensions[X509ExtensionOid.CAVersion];
        // if CA Version in issuer certificate is presented, copy it to CRL
        // otherwise, skip CA Version.
        if (e != null) {
            _extensions.Add(e);
        }
    }
    void processCrlNumberExtension() {
        /* the following rules apply:
        3. if CrlNumberIncrement is greater than zero and there is no CRL Number extension in existing CRL,
            CrlNumberIncrement is set as CRL Number extension value.
        4. if CrlNumberIncrement is greater than zero and there is existing CRL Number extension in existing CRL,
            CRL Number in existing extension is incremented by CrlNumberIncrement.
        5. if CrlNumberIncrement is zero or negative, no CRL Number extension is added.
        */
        BigInteger newCrlVersion = 0;
        X509Extension crlNumberExt = _extensions.FirstOrDefault(x => x.Oid.Value == X509ExtensionOid.CRLNumber);
        if (crlNumberExt != null) {
            newCrlVersion = ((X509CRLNumberExtension)crlNumberExt).CRLNumber + CrlNumberIncrement;
        }
        if (CrlNumberIncrement > 0) {
            GenericArray.RemoveExtension(_extensions, X509ExtensionOid.CRLNumber);
            crlNumberExt = new X509CRLNumberExtension(newCrlVersion, false);
            _extensions.Add(crlNumberExt);
        }
    }
    void processNextCrlPublishExtension() {
        if (NextCrlPublish == null) {
            return;
        }
        var nextCrlPublish = (DateTime)NextCrlPublish;
        // validate if NextCrlPublish is within ThisUpdate and NextUpdate.
        if (nextCrlPublish > ThisUpdate && nextCrlPublish <= NextUpdate) {
            _extensions.Add(new X509NextCRLPublishExtension((DateTime)NextCrlPublish, false));
        }
    }

    List<Byte> buildTbs(Byte[] signatureAlgorithm, X509Certificate2 issuer) {
        if (String.IsNullOrEmpty(issuer.Issuer)) {
            throw new ArgumentException("Subject name is empty.");
        }
        // coerce hashing algorithm
        if (HashingAlgorithm == null) {
            HashingAlgorithm = new Oid(AlgorithmOid.SHA256);
        }
        // coerce version
        if (_extensions.Count > 0) {
            Version = 2;
        }
        // coerce validity
        if (NextUpdate == null || NextUpdate.Value <= ThisUpdate) {
            NextUpdate = ThisUpdate.AddDays(7);
        }


        var rawBytes = new List<Byte>();
        // algorithm
        rawBytes.AddRange(signatureAlgorithm);
        // issuer
        rawBytes.AddRange(issuer.SubjectName.RawData);
        // thisUpdate
        rawBytes.AddRange(Asn1DateTime.CreateRfcDateTime(ThisUpdate).GetRawData());
        // nextUpdate. Not null at this point, because we do not support CRL generation with infinity validity.
        rawBytes.AddRange(Asn1DateTime.CreateRfcDateTime(NextUpdate.Value).GetRawData());
        // revokedCerts
        if (RevokedCertificates.Count > 0) {
            rawBytes.AddRange(RevokedCertificates.Encode());
        }
        // extensions
        if (Version == 2) {
            // insert version at the beginning.
            rawBytes.InsertRange(0, new Asn1Integer(Version - 1).GetRawData());
            generateExtensions(issuer);
            rawBytes.AddRange(Asn1Utils.Encode(Extensions.Encode(), 160));
        }
        // generate tbs
        return new List<Byte>(Asn1Utils.Encode(rawBytes.ToArray(), 48));
    }

    /// <summary>
    /// Hashes and encodes CRL object from builder information. Instead of signing, CRL is hashed.
    /// </summary>
    /// <param name="hasherInfo">
    /// Issuer certificate to use as a CRL issuer. Issuer certificate is not required to have private key.
    /// </param>
    /// <returns>An instance of generated CRL object.</returns>
    public X509CRL2 BuildAndHash(X509Certificate2 hasherInfo) {
        var dummyBlob = new SignedContentBlob(new Byte[] { 0 }, ContentBlobType.ToBeSignedBlob);
        dummyBlob.Hash(HashingAlgorithm);
        List<Byte> tbs = buildTbs(dummyBlob.SignatureAlgorithm.RawData, hasherInfo);
        var blob = new SignedContentBlob(tbs.ToArray(), ContentBlobType.ToBeSignedBlob);
        blob.Hash(HashingAlgorithm);
        return new X509CRL2(blob.Encode());
    }
    /// <summary>
    /// Signs and encodes CRL object from builder information.
    /// </summary>
    /// <param name="signerInfo">Certificate which is used to sign CRL.</param>
    /// <returns>An instance of generated signed CRL object.</returns>
    public X509CRL2 BuildAndSign(ICryptSigner signerInfo) {
        if (signerInfo == null) { throw new ArgumentNullException(nameof(signerInfo)); }

        // create dummy blob, sign/hash it to get proper encoded signature algorithm identifier.
        var dummyBlob = new SignedContentBlob(new Byte[] { 0 }, ContentBlobType.ToBeSignedBlob);
        dummyBlob.Sign(signerInfo);
        // generate tbs
        List<Byte> tbs = buildTbs(dummyBlob.SignatureAlgorithm.RawData, signerInfo.SignerCertificate);

        // now create correct blob and sign/hash it
        var blob = new SignedContentBlob(tbs.ToArray(), ContentBlobType.ToBeSignedBlob);
        blob.Sign(signerInfo);
        return new X509CRL2(blob.Encode());
    }
}