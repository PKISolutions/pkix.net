using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.ManagedAPI;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography.Pkcs;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a Microsoft Certificate Trust List (CTL) object.
/// </summary>
public class X509CertificateTrustList {
    readonly Oid ctlOid = new("1.3.6.1.4.1.311.10.1");
    readonly List<Oid> _usages = new();
    readonly X509CertificateTrustListEntryCollection _entries = new();
    readonly List<X509Extension> _extensions = new();
    readonly List<Byte> _rawData = new();

    DefaultSignedPkcs7 cms;
    BigInteger? sequenceNumber;

    /// <summary>
    /// Initializes a new instance of the <strong>X509CertificateTrustList</strong> class using the path to a CTL file. 
    /// </summary>
    /// <param name="path">The path to a CTL file (*.stl).</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>path</strong> parameter is null or empty.
    /// </exception>
    public X509CertificateTrustList(String path) {
        if (String.IsNullOrEmpty(path)) {
            throw new ArgumentNullException(nameof(path));
        }
        decode(Crypt32Managed.CryptFileToBinary(path));
    }

    /// <summary>
    /// Initializes a new instance of the <strong>X509CertificateTrustList</strong> class defined from a sequence of bytes representing
    /// an X.509 certificate trust list.
    /// </summary>
    /// <param name="rawData">A byte array containing data from an X.509 CTL.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>rawData</strong> parameter is null.
    /// </exception>
    public X509CertificateTrustList(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        decode(rawData);
    }

    /// <summary>
    /// Gets X.509 certificate trust list (<strong>CTL</strong>) version. Currently, only Version 1 is defined.
    /// </summary>
    public Int32 Version => 1;
    /// <summary>
    /// Gets a collection of <strong>OIDs</strong> that represents intended usages of the certificate trust list.
    /// </summary>
    public OidCollection SubjectUsage {
        get {
            var retValue = new OidCollection();
            foreach (Oid item in _usages) {
                retValue.Add(item);
            }
            return retValue;
        }
    }
    /// <summary>
    /// Gets a string that uniquely identifies the list. This member is used to augment the SubjectUsage and further specifies the list when desired.
    /// </summary>
    public String ListIdentifier { get; private set; }
    /// <summary>
    /// Gets a monotonically increasing number for each update of the <strong>CTL</strong>.
    /// </summary>
    public String SequenceNumber { get; private set; }
    /// <summary>
    /// Gets the issue date of this.
    /// </summary>
    public DateTime ThisUpdate { get; private set; }
    /// <summary>
    /// Indication of the date and time for the CTL's next available scheduled update.
    /// </summary>
    public DateTime? NextUpdate { get; private set; }
    /// <summary>
    /// Gets the algorithm type of the <see cref="X509CertificateTrustListEntry.Thumbprint">Thumbprint</see> in <see cref="X509CertificateTrustListEntry"/> members of the
    /// <see cref="Entries"/> member array.
    /// </summary>
    public Oid SubjectAlgorithm { get; private set; }
    /// <summary>
    /// Gets a collection of <see cref="X509CertificateTrustListEntry"/> elements.
    /// </summary>
    public X509CertificateTrustListEntryCollection Entries => new(_entries);
    /// <summary>
    /// Gets a collection of <see cref="X509Extension">X509Extension</see> objects.
    /// </summary>
    /// <remarks><p>Version 1 CTLs do not support extensions and this property is always empty for them.</p>
    /// </remarks>
    public X509ExtensionCollection Extensions {
        get {
            var retValue = new X509ExtensionCollection();
            foreach (X509Extension item in _extensions) {
                retValue.Add(item);
            }
            return retValue;
        }
    }
    /// <summary>
    /// Gets the raw data of a certificate trust list.
    /// </summary>
    public Byte[] RawData => _rawData.ToArray();

    void reset() {
        _usages.Clear();
        _entries.Clear();
        _extensions.Clear();
        _rawData.Clear();
        sequenceNumber = null;
    }
    void decode(Byte[] rawData) {
        reset();
        _rawData.AddRange(rawData);
        cms = new DefaultSignedPkcs7(rawData);
        if (cms.ContentType.Value != ctlOid.Value) {
            throw new ArgumentException("Decoded data is not valid certificate trust list.");
        }
        var asn = new Asn1Reader(Asn1Utils.Encode(cms.Content, 48));
        asn.MoveNextAndExpectTags(48);
        decodeUsages(asn);
        Boolean reachedEnd = false;
        while (asn.MoveNextSibling()) {
            if (reachedEnd) {
                break;
            }
            switch (asn.Tag) {
                case (Byte)Asn1Type.OCTET_STRING:
                    decodeListIdentifier(asn);
                    break;
                case (Byte)Asn1Type.INTEGER:
                    decodeSequenceNumber(asn);
                    break;
                case (Byte)Asn1Type.UTCTime:
                case (Byte)Asn1Type.GeneralizedTime:
                    decodeValidity(asn);
                    reachedEnd = true;
                    break;
                default:
                    reachedEnd = true;
                    break;
            }
        }
        decodeAlgId(asn);
        asn.MoveNextSibling();
        decodeEntries(asn);
        if (asn.MoveNextSibling()) {
            decodeExtensions(asn);
        }
    }
    void decodeUsages(Asn1Reader asn) {
        var eku = new X509EnhancedKeyUsageExtension(new AsnEncodedData(asn.GetTagRawData()), false);
        foreach (Oid usage in eku.EnhancedKeyUsages) {
            _usages.Add(usage);
        }
    }
    void decodeListIdentifier(Asn1Reader asn) {
        ListIdentifier = Encoding.Unicode.GetString(asn.GetPayload()).TrimEnd('\0');
    }
    void decodeSequenceNumber(Asn1Reader asn) {
        sequenceNumber = new Asn1Integer(asn.GetTagRawData()).Value;
        SequenceNumber = AsnFormatter.BinaryToString(asn.GetPayload());
    }
    void decodeValidity(Asn1Reader asn) {
        ThisUpdate = Asn1Utils.DecodeDateTime(asn.GetTagRawData());
        Int32 offset = asn.Offset;
        asn.MoveNext();
        if (asn.Tag == (Byte)Asn1Type.UTCTime || asn.Tag == (Byte)Asn1Type.GeneralizedTime) {
            NextUpdate = Asn1Utils.DecodeDateTime(asn.GetTagRawData());
        } else {
            asn.Seek(offset);
        }
        //asn.MoveToPosition(offset);
    }
    void decodeAlgId(Asn1Reader asn) {
        var algId = new AlgorithmIdentifier(asn.GetTagRawData());
        SubjectAlgorithm = algId.AlgorithmId;
    }
    void decodeEntries(Asn1Reader asn) {
        var collection = new X509CertificateTrustListEntryCollection();
        collection.Decode(asn.GetTagRawData());
        IDictionary<String, X509Certificate2> hashList = hashCerts();
        foreach (X509CertificateTrustListEntry entry in collection) {
            if (hashList.ContainsKey(entry.Thumbprint)) {
                entry.Certificate = hashList[entry.Thumbprint];
            }
        }
        if (collection.Count > 0) {
            _entries.AddRange(collection);
        }
    }
    IDictionary<String, X509Certificate2> hashCerts() {
        var hashList = new Dictionary<String, X509Certificate2>(StringComparer.InvariantCultureIgnoreCase);
        using var hasher = HashAlgorithm.Create(SubjectAlgorithm.FriendlyName);
        if (hasher == null) {
            return hashList;
        }
        var certList = new X509Certificate2Collection();
        certList.AddRange(cms.Certificates);
        foreach (StoreName storeName in new[] { StoreName.Root, StoreName.CertificateAuthority, StoreName.AuthRoot }) {
            var store = new X509Store(storeName, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            certList.AddRange(store.Certificates);
            store.Close();
        }
        foreach (X509Certificate2 cmsCert in certList) {
            String hashString = AsnFormatter.BinaryToString(hasher.ComputeHash(cmsCert.RawData), format: EncodingFormat.NOCRLF);
            if (hashList.ContainsKey(hashString)) {
                continue;
            }
            hashList.Add(hashString, cmsCert);
        }

        return hashList;
    }
    void decodeExtensions(Asn1Reader asn) {
        var extensions = new X509ExtensionCollection();
        extensions.Decode(asn.GetTagRawData());
        foreach (X509Extension extension in extensions) {
            _extensions.Add(extension);
        }
    }
    void processCertificates() {

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
        var tspReq = new TspRfc3161Request(hashAlgorithm, cms.SignerInfos[signerInfoIndex].EncryptedHash) {
            TsaUrl = new Uri(tsaUrl)
        };
        TspResponse rsp = tspReq.SendRequest();

        var builder = new SignedCmsBuilder(cms);
        builder.AddTimestamp(rsp, 0);
        decode(builder.Encode().RawData);
    }
    /// <summary>
    /// Gets the sequence number as integral value.
    /// </summary>
    /// <returns>
    ///     Integral value of sequence number. This method returns <strong>null</strong> if decoded trust list does not have
    ///     sequence number information.
    /// </returns>
    public BigInteger? GetSequenceNumber() {
        return sequenceNumber;
    }
}