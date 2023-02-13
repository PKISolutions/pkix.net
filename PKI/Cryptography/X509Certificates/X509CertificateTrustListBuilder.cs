using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.Pkcs;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Contains properties and methods used to create and sign X.509 certificate trust list.
/// </summary>
public class X509CertificateTrustListBuilder {
    const String CTL_CONTENT_TYPE = "1.3.6.1.4.1.311.10.1";
    readonly Oid oid = new(CTL_CONTENT_TYPE);

    /// <summary>
    /// Initializes a new instance of <strong>X509CertificateTrustListBuilder</strong>
    /// </summary>
    public X509CertificateTrustListBuilder() { }

    /// <summary>
    /// Initializes a new instance of <strong>X509CertificateTrustListBuilder</strong> from existing trust list. All data from existing
    /// list is copied to builder.
    /// </summary>
    /// <param name="ctl">Existing trust list to use as a base object.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>ctl</strong> parameter is null.
    /// </exception>
    public X509CertificateTrustListBuilder(X509CertificateTrustList ctl) {
        if (ctl == null) {
            throw new ArgumentNullException(nameof(ctl));
        }
        ListIdentifier = ctl.ListIdentifier;
        SequenceNumber = ctl.GetSequenceNumber();
        foreach (Oid usage in ctl.SubjectUsage) {
            SubjectUsages.Add(usage);
        }
        Entries.AddRange(ctl.Entries);
        HashAlgorithm = ctl.SubjectAlgorithm;
        ThisUpdate = ctl.ThisUpdate;
        NextUpdate = ctl.NextUpdate;
    }

    /// <summary>
    /// Gets or sets the trust list identifier. Often, it is a friendly name of the list.
    /// </summary>
    public String ListIdentifier { get; set; }
    /// <summary>
    /// Gets or sets the monotonically increasing number for each update of the CTL.
    /// </summary>
    public BigInteger? SequenceNumber { get; set; }
    /// <summary>
    /// Gets a list that identifies the intended usage of the list as a sequence of object identifiers. This is the same as in
    /// the Enhanced Key Usage extension.
    /// </summary>
    public OidCollection SubjectUsages { get; } = new();
    /// <summary>
    /// Gets a collection of trust list entries associated with trust list.
    /// </summary>
    public X509CertificateTrustListEntryCollection Entries { get; } = new();
    /// <summary>
    /// Gets or sets the hashing algorithm used to create trust list entries. Default algorithm is SHA1.
    /// </summary>
    public Oid HashAlgorithm { get; set; } = new(AlgorithmOid.SHA1);
    /// <summary>
    /// Gets or sets the date and time when trust list validity begins. Default value is current date and time.
    /// </summary>
    public DateTime ThisUpdate { get; set; } = DateTime.UtcNow;
    /// <summary>
    /// Gets or sets the expiration date and time for trust list. If not set, trust list is valid indefinitely.
    /// </summary>
    public DateTime? NextUpdate { get; set; }

    Byte[] encodeCTL() {
        var builder = new Asn1Builder()
            .AddDerData(new X509EnhancedKeyUsageExtension(SubjectUsages, false).RawData);
        var rawData = new List<Byte>(new X509EnhancedKeyUsageExtension(SubjectUsages, false).RawData);
        if (!String.IsNullOrEmpty(ListIdentifier)) {
            builder.AddOctetString(Encoding.Unicode.GetBytes(ListIdentifier + "\0"));
        }
        if (SequenceNumber != null) {
            builder.AddInteger(SequenceNumber.Value);
        }
        builder.AddDerData(Asn1Utils.EncodeDateTime(ThisUpdate.ToUniversalTime()));
        if (NextUpdate != null) {
            builder.AddDerData(Asn1Utils.EncodeDateTime(NextUpdate.Value.ToUniversalTime()));
        }
        return builder.AddDerData(new AlgorithmIdentifier(HashAlgorithm, Array.Empty<Byte>()).RawData)
            .AddDerData(Entries.Encode())
            .GetRawData();
    }


    /// <summary>
    ///     Encodes and signs current trust list using signer certificate and optional certificate chain to include in CTL.
    /// </summary>
    /// <param name="signer">signing object that contains public certificate, private key and signing configuration.</param>
    /// <param name="chain">
    ///     Signing certificate chain to add to CMS. This parameter is optional. If not specified, only leaf (signing) certificate
    ///     is added to certificate list.
    /// </param>
    /// <returns>
    ///     An instance of <see cref="SysadminsLV.PKI.Cryptography.X509Certificates.X509CertificateTrustList"/> class that represents signed certificate trust list.
    /// </returns>
    public X509CertificateTrustList Sign(ICryptSigner signer, X509Certificate2Collection chain) {
        var cmsBuilder = new SignedCmsBuilder(oid, encodeCTL());
        cmsBuilder.DigestAlgorithms.Add(new AlgorithmIdentifier(signer.HashingAlgorithm, Array.Empty<Byte>()));
        foreach (X509CertificateTrustListEntry entry in Entries.Where(x => x.Certificate != null)) {
            cmsBuilder.Certificates.Add(entry.Certificate);
        }
        DefaultSignedPkcs7 signedCms = cmsBuilder.Sign(signer, chain);
        return new X509CertificateTrustList(signedCms.RawData);
    }
}