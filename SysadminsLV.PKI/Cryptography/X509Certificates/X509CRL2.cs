using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI;
using SysadminsLV.PKI.CLRExtensions;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace System.Security.Cryptography.X509Certificates;

/// <summary>
/// Provides methods that help you use X.509 certificate revocation lists (CRL).
/// </summary>
public class X509CRL2 {
    readonly X509CRLEntryCollection _revokedCerts = new();
    readonly Byte[] _rawData;
    readonly X509ExtensionCollection _extensions = new();

    Int32 sigUnused;
    Byte[] signature;
    /// <summary>
    /// Initializes a new instance of the <see cref="X509CRL2"/> class using the path to a CRL file. 
    /// </summary>
    /// <param name="path">The path to a CRL file.</param>
    public X509CRL2(String path) {
        _rawData = CryptBinaryConverter.CryptFileToBinary(path);
        m_decode();
    }
    /// <summary>
    /// Initializes a new instance of the <see cref="X509CRL2"/> class defined from a sequence of bytes representing
    /// an X.509 certificate revocation list.
    /// </summary>
    /// <param name="rawData">A byte array containing data from an X.509 CRL.</param>
    /// <exception cref="ArgumentNullException"></exception>
    public X509CRL2(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        _rawData = rawData.ToArray();
        m_decode();
    }

    /// <summary>
    /// Gets the X.509 format version of a certificate revocation list.
    /// </summary>
    /// <remarks>There are several versions of X.509 CRLs. This property identifies which format the certificate
    /// revocation list uses. For example, "2" is returned for a version 2 certificate revocation list.
    /// <p>RFC5280 defines only 2 versions: v1 and v2.</p></remarks>
    public Int32 Version { get; private set; }
    /// <summary>
    /// Gets the type of a certificate revocation list. Value can be either <strong>Base CRL</strong> or <strong>Delta CRL</strong>.
    /// </summary>
    /// <remarks><p><strong>Base CRL</strong> includes revocation information about all certificates revoked during entire CA lifetime.</p>
    /// <p><strong>Delta CRL</strong> includes revocation information about certificates revoked only since the last Base CRL was issued.</p></remarks>
    public X509CrlType Type { get; private set; }
    /// <summary>
    /// Gets the distinguished name of the CRL issuer.
    /// </summary>
    /// <remarks>This property contains the name of the certificate authority (CA) that issued the CRL. To obtain the
    /// name of the issuer, use the GetNameInfo method. The distinguished name for the CRL is a textual
    /// representation of the CRL issuer. This representation consists of name attributes (for example,
    /// "CN=MyName, OU=MyOrgUnit, C=US").</remarks>
    public X500DistinguishedName IssuerName { get; private set; }
    /// <summary>
    /// Gets the textual representation of the CRL issuer (in X.500 name format).
    /// </summary>
    /// <remarks>This property contains the name of the certificate authority (CA) that issued the CRL.
    /// The distinguished name for the certificate is a textual representation of the CRL issuer. This representation
    /// consists of name attributes (for example, "CN=MyName, OU=MyOrgUnit, C=US").</remarks>
    public String Issuer => IssuerName.Name;

    /// <summary>
    /// Gets the issue date of this CRL.
    /// </summary>
    public DateTime ThisUpdate { get; private set; }
    /// <summary>
    /// Gets the date by which the next CRL will be issued. The next CRL could be issued before the indicated date, but it will
    /// not be issued any later than the indicated date.
    /// </summary>
    /// <remarks>CRL issuers SHOULD issue CRLs with a NextUpdate time equal to or later than all previous CRLs.</remarks>
    public DateTime? NextUpdate { get; private set; }
    /// <summary>
    /// Gets the algorithm used to create the signature of a CRL.
    /// </summary>
    /// <remarks>The object identifier <see cref="Oid">(Oid)</see> identifies the type of signature
    /// algorithm used by the CRL.</remarks>
    public Oid SignatureAlgorithm { get; private set; }
    /// <summary>
    /// Gets the CRL sequential number.
    /// </summary>
    public BigInteger CRLNumber { get; private set; }
    /// <summary>
    /// Gets a collection of <see cref="X509Extension">X509Extension</see> objects.
    /// </summary>
    /// <remarks><p>Version 1 CRLs do not support extensions and this property is always empty for them.</p>
    /// <p>The extensions defined in the X.509 v2 CRL format allow additional data to be included 
    /// in the CRL. A number of extensions are defined by ISO in the X.509 v3 definition as well 
    /// as by PKIX in RFC 5280, "Certificate and Certificate Revocation List (CRL) Profile." 
    /// Common extensions include information regarding key identifiers (X509AuthorityKeyIdentifierExtension),
    /// CRL sequence numbers, additional revocation information (Delta CRL Locations), and other uses.</p>
    /// </remarks>
    public X509ExtensionCollection Extensions {
        get {
            var retValue = new X509ExtensionCollection();
            foreach (X509Extension extension in _extensions) {
                retValue.Add(extension);
            }

            return retValue;
        }
    }
    /// <summary>
    /// Gets a collection of <see cref="X509CRLEntry">X509CRLEntry</see> objects.
    /// </summary>
    /// <remarks><see cref="X509CRLEntry"/> object represents a CRL entry.
    /// Each entry contains at least the following information: <see cref="X509CRLEntry.SerialNumber">SerialNumber</see>
    /// of revoked certificate and <see cref="X509CRLEntry.RevocationDate">RevocationDate</see> that represents a date
    /// and time at which certificate was revoked. Additionally, revocation entry may contain additional information,
    /// such revocation reason.</remarks>
    public X509CRLEntryCollection RevokedCertificates => new(_revokedCerts);
    /// <summary>
    /// Gets the raw data of a certificate revocation list.
    /// </summary>
    public Byte[] RawData => _rawData.ToArray();
    /// <summary>
    /// Gets a thumbprint of the current CRL object. Default thumbprint algorithm is SHA256.
    /// </summary>
    /// <remarks>
    /// The thumbprint is dynamically generated using the SHA256 algorithm and does not physically exist
    /// in the certificate revocation list. Since the thumbprint is a unique value for the certificate,
    /// it is commonly used to find a particular certificate revocation list in a certificate store.</remarks>
    public String Thumbprint { get; private set; }

    void m_decode() {
        try {
            Type = X509CrlType.BaseCrl;
            var signedInfo = new SignedContentBlob(_rawData, ContentBlobType.SignedBlob);
            // signature and alg
            signature = signedInfo.Signature.Value;
            sigUnused = signedInfo.Signature.UnusedBits;
            SignatureAlgorithm = signedInfo.SignatureAlgorithm.AlgorithmId;
            // tbs
            var asn = new Asn1Reader(signedInfo.ToBeSignedData);
            if (!asn.MoveNext()) { throw new Asn1InvalidTagException(); }
            // version
            if (asn.Tag == (Byte)Asn1Type.INTEGER) {
                Version = (Int32)Asn1Utils.DecodeInteger(asn.GetTagRawData()) + 1;
                asn.MoveNextSibling();
            } else {
                Version = 1;
            }
            // hash algorithm
            var h = new AlgorithmIdentifier(asn.GetTagRawData());
            if (h.AlgorithmId.Value != SignatureAlgorithm.Value) {
                throw new CryptographicException("Algorithm mismatch.");
            }
            if (!asn.MoveNextSibling()) { throw new Asn1InvalidTagException(); }
            // issuer
            IssuerName = new X500DistinguishedName(asn.GetTagRawData());
            // NextUpdate, RevokedCerts and Extensions are optional. Ref: RFC5280, p.118
            if (!asn.MoveNextSibling()) { throw new Asn1InvalidTagException(); }
            switch (asn.Tag) {
                case (Byte)Asn1Type.UTCTime:
                    ThisUpdate = new Asn1UtcTime(asn.GetTagRawData()).Value;
                    break;
                case (Byte)Asn1Type.GeneralizedTime:
                    ThisUpdate = Asn1Utils.DecodeGeneralizedTime(asn.GetTagRawData());
                    break;
                default:
                    throw new Asn1InvalidTagException();
            }
            if (!asn.MoveNextSibling()) { return; }
            switch (asn.Tag) {
                case (Byte)Asn1Type.UTCTime:
                case (Byte)Asn1Type.GeneralizedTime:
                    switch (asn.Tag) {
                        case (Byte)Asn1Type.UTCTime:
                            NextUpdate = new Asn1UtcTime(asn.GetTagRawData()).Value;
                            break;
                        case (Byte)Asn1Type.GeneralizedTime:
                            NextUpdate = Asn1Utils.DecodeGeneralizedTime(asn.GetTagRawData());
                            break;
                        default:
                            throw new Asn1InvalidTagException();
                    }
                    if (!asn.MoveNextSibling()) { return; }
                    if (asn.Tag == 48) {
                        _revokedCerts.Decode(asn);
                        if (!asn.MoveNextSibling()) { return; }
                        readExtensions(asn);
                    } else {
                        readExtensions(asn);
                    }
                    break;
                case 48:
                    if (asn.Tag == 48) {
                        _revokedCerts.Decode(asn);
                        if (!asn.MoveNextSibling()) { return; }
                        readExtensions(asn);
                    } else {
                        readExtensions(asn);
                    }
                    break;
                default:
                    readExtensions(asn);
                    break;
            }
            calculateThumbprint();
        } catch (Exception e) {
            throw new CryptographicException("Cannot find the requested object.", e);
        }
    }
    void readExtensions(Asn1Reader asn) {
        // extensions are explicitly tagged, so move to inner
        asn.MoveNext();
        // and then decode
        _extensions.Decode(asn);
        if (_extensions[X509ExtensionOid.DeltaCRLIndicator] != null) {
            Type = X509CrlType.DeltaCrl;
        }
        var crlNumExt = (X509CRLNumberExtension)_extensions[X509ExtensionOid.CRLNumber];
        CRLNumber = crlNumExt?.CRLNumber ?? 0;
    }
    void calculateThumbprint() {
        var sb = new StringBuilder();
        using (var hasher = SHA256.Create()) {
            foreach (Byte b in hasher.ComputeHash(_rawData)) {
                sb.AppendFormat("{0:X2}", b);
            }
        }
        Thumbprint = sb.ToString();
    }
    void genBriefString(StringBuilder SB) {
        String n = Environment.NewLine;
        SB.Append($@"[Type]
  {Type}


[Issuer]
  {Issuer}


[This Update]
  {ThisUpdate}


[Next Update]
  ");
        if (NextUpdate == null) {
            SB.Append("Infinity");
        } else {
            SB.Append(NextUpdate);
        }
        SB.Append($"{n}{n}[Revoked Certificate Count]{n}  {_revokedCerts.Count}{n}{n}");
    }
    void genVerboseString(StringBuilder SB, Int32 revCertEntries) {
        String n = Environment.NewLine;
        SB.AppendLine("X509 Certificate Revocation List:");
        SB.AppendLine($"Version: {Version}");
        SB.AppendLine("Issuer: ");
        String[] tokens = Issuer.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
        for (Int32 index = 0; index < tokens.Length; index++) {
            tokens[index] = "    " + tokens[index].Trim();
        }
        SB.AppendLine(String.Join(n, tokens));
        SB.AppendLine();
        SB.AppendLine($"This Update: {ThisUpdate}");
        SB.AppendLine(NextUpdate == null
            ? "Next Update: Infinity"
            : $"Next Update: {NextUpdate}");
        SB.AppendLine();
        SB.AppendLine($"CRL Entries: {_revokedCerts.Count}");
        if (_revokedCerts.Count > 0) {
            Int32 upperBound = _revokedCerts.Count;
            Int32 truncatedCount = 0;
            if (revCertEntries > 0) {
                truncatedCount = _revokedCerts.Count - revCertEntries;
                upperBound = Math.Min(revCertEntries, _revokedCerts.Count);
            }

            for (Int32 index = 0; index < upperBound; index++) {
                X509CRLEntry revCert = _revokedCerts[index];
                SB.AppendLine($"    Serial Number: {revCert.SerialNumber}");
                SB.AppendLine($"    Revocation Date: {revCert.RevocationDate}");
                if (revCert.ReasonCode != 0) {
                    SB.AppendLine($"    Revocation Reason: {revCert.ReasonMessage} ({revCert.ReasonCode})");
                }

                SB.AppendLine();
            }

            if (truncatedCount > 0) {
                SB.AppendLine("    <...>");
                SB.AppendLine($"    Next {truncatedCount} entries are truncated from dump.");
            }
        }

        SB.AppendLine($"CRL Extensions: {_extensions.Count}");
        if (_extensions.Count > 0) {
            foreach (X509Extension ext in _extensions) {
                SB.Append($"  OID={ext.Oid.Format(true)}, ");
                SB.AppendLine($"Critical={ext.Critical}, Length={ext.RawData.Length} ({ext.RawData.Length:x2}):");
                SB.AppendLine($"    {ext.Format(true).Replace(n, $"{n}    ").TrimEnd()}");
                SB.AppendLine();
            }
        }
        SB.AppendLine("Signature Algorithm:");
        SB.AppendLine($"    Algorithm ObjectId: {SignatureAlgorithm.Format(true)}");
        SB.Append($"Signature: Unused bits={sigUnused}{n}    ");
        String tempString = AsnFormatter.BinaryToString(signature, EncodingType.HexAddress);
        SB.Append($"{tempString.Replace(n, $"{n}    ").TrimEnd()}");
    }

    /// <summary>
    /// Exports the current X509CRL2 object to a file.
    /// </summary>
    /// <param name="path">The path to a CRL file.</param>
    /// <param name="encoding">Encoding of the exported file.</param>
    public void Export(String path, EncodingType encoding = EncodingType.Base64CrlHeader) {
        String Base64;

        switch (encoding) {
            case EncodingType.Base64Header:
                Base64 = AsnFormatter.BinaryToString(_rawData, EncodingType.Base64CrlHeader);
                break;
            case EncodingType.Binary:
                File.WriteAllBytes(path, _rawData);
                return;
            default:
                Base64 = AsnFormatter.BinaryToString(_rawData, encoding);
                break;
        }

        File.WriteAllText(path, Base64);
    }
    /// <summary>
    /// Encodes the current X509CRL2 object to a form specified in the <strong>encoding</strong> parameter.
    /// </summary>
    /// <param name="encoding">Encoding type. Default is <strong>CRYPT_STRING_BASE64X509CRLHEADER</strong>.</param>
    /// <returns>Encoded text.</returns>
    /// <remarks>
    ///		The following encoding types are <strong>not</strong> supported:
    ///		<list type="bullet">
    ///			<item>Binary</item>
    ///			<item>Base64Any</item>
    ///			<item>StringAny</item>
    ///			<item>HexAny</item>
    ///		</list>
    /// </remarks>
    /// <exception cref="ArgumentException">Specified encoding type is not supported.</exception>
    public String Encode(EncodingType encoding = EncodingType.Base64CrlHeader) {
        if (encoding == EncodingType.Binary) {
            throw new ArgumentException("Specified encoding is not supported.");
        }
        return AsnFormatter.BinaryToString(_rawData, encoding);
    }
    /// <inheritdoc />
    public override String ToString() {
        var SB = new StringBuilder();
        genBriefString(SB);
            
        return SB.ToString();
    }
    ///  <summary>
    ///  Displays an X.509 certificate revocation list in text format. This method is obsolete.
    ///  </summary>
    ///  <param name="verbose">
    /// 		Specifies whether the simple or enhanced/verbose output is necessary.
    /// 		If this parameter is set to <strong>False</strong> (default value), the method returns a brief information about the
    /// 		current object. If this parameter is set to <strong>True</strong>, the method will return a full dump of the
    /// 		current object.
    ///  </param>
    ///  <returns>The CRL information.</returns>
    ///  <remarks>If the object is not initialized, the method returns class name.</remarks>
    [Obsolete]
    public String ToString(Boolean verbose) {
        var SB = new StringBuilder();
        if (verbose) {
            genVerboseString(SB, 0);
        } else {
            genBriefString(SB);
        }
        return SB.ToString();
    }
    /// <summary>
    /// Displays an X.509 certificate revocation list in text format.
    /// </summary>
    /// <param name="revCertCount">
    ///     Specifies the number of revoked certificate entries included in text dump. Zero value means that all entries
    ///     are included which may negatively affect performance on large CRLs.
    /// </param>
    /// <returns>The CRL text dump.</returns>
    public String ToString(Int32 revCertCount) {
        var SB = new StringBuilder();
        genVerboseString(SB, revCertCount);

        return SB.ToString();
    }
    ///  <summary>
    ///		Verifies whether the specified certificate is an issuer of this CRL by verifying CRL signature
    ///		against specified certificate's public key.
    ///  </summary>
    ///  <param name="issuer">
    ///		A potential issuer's certificate.
    /// </param>
    /// <param name="strict">
    ///		Specifies whether to perform CRL issuer and certificate's subject name binary comparison. This parameter is not implemented.
    /// </param>
    /// <exception cref="CryptographicException">
    /// 	The data is invalid.
    ///  </exception>
    ///  <returns>
    /// 		<strong>True</strong> if the specified certificate is signed this CRL. Otherwise <strong>False</strong>.
    ///  </returns>
    public Boolean VerifySignature(X509Certificate2 issuer, Boolean strict = false) {
        var signedBlob = new SignedContentBlob(_rawData, ContentBlobType.SignedBlob);
        return issuer.PublicKey.VerifySignature(signedBlob);
    }
    /// <summary>
    /// Verifies whether the specified certificate is in the current revocation list.
    /// </summary>
    /// <param name="cert">Certificate to verify.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>cert</strong> parameter is null.
    /// </exception>
    /// <exception cref="PKI.Exceptions.UninitializedObjectException">
    ///     An object is not initialized.
    /// </exception>
    /// <returns>
    ///     <strong>True</strong> if the specified certificate is presented in the CRL. Otherwise <strong>False</strong>.
    /// </returns>
    /// <remarks>This method do not check, whether the certificate was issued by the same issuer, as this CRL.</remarks>
    public Boolean CertificateInCrl(X509Certificate2 cert) {
        if (cert == null) {
            throw new ArgumentNullException(nameof(cert));
        }
        if (_revokedCerts.Count < 1) {
            return false;
        }
        return _revokedCerts[cert.SerialNumber] == null;
    }
    /// <summary>
    /// Gets certificate revocation list sequence number.
    /// </summary>
    /// <returns>Certificate revocation list sequence number.</returns>
    /// <remarks>If CRL is X.509 CRL Version 1, or CRL does not contains 'CRL Number' extension, a zero is returned.</remarks>
    public BigInteger GetCRLNumber() {
        X509Extension e = _extensions[X509ExtensionOid.CRLNumber];
        return ((X509CRLNumberExtension)e)?.CRLNumber ?? 0;
    }
    /// <summary>
    /// Gets the date and time when the next CRL is planned to be published. The method uses either <strong>Next CRL Publish</strong> extension
    /// or <strong>NextUpdate</strong> field to determine when a newer version should be issued.
    /// </summary>
    /// <returns>A <see cref="DateTime"/> object, or <strong>NULL</strong>, if CRL is valid infinitely and no updates are expected.</returns>
    public DateTime? GetNextPublish() {
        if (_extensions == null) { return NextUpdate; }
        X509Extension e = _extensions[X509ExtensionOid.NextCRLPublish];
        return e == null ? NextUpdate : Asn1Utils.DecodeDateTime(e.RawData);
    }
    /// <summary>
    /// Indicates whether the current Base CRL has configured to use Delta CRLs too.
    /// </summary>
    /// <returns><strong>True</strong> is the current CRL is configured to use Delta CRLs, otherwise <strong>False</strong>.</returns>
    /// <remarks>If the current CRL type already is Delta CRL, the method returns <strong>False</strong>.</remarks>
    public Boolean HasDelta() {
        return Type != X509CrlType.DeltaCrl && _extensions[X509ExtensionOid.FreshestCRL] != null;
    }
    /// <summary>
    /// Determines whether the specified object is equal to the current object. Two CRLs are equal when
    /// they have same version, type, issuer, CRL number and <see cref="ThisUpdate"/> values.
    /// </summary>
    /// <inheritdoc cref="Object.Equals" select="param|returns"/>
    public override Boolean Equals(Object obj) {
        return !(obj is null) &&
               (ReferenceEquals(this, obj)
                || obj.GetType() == GetType()
                && Equals((X509CRL2)obj));
    }
    Boolean Equals(X509CRL2 other) {
        return Version == other.Version
               && Type == other.Type
               && IssuerName.Equals(other.IssuerName)
               && ThisUpdate.Equals(other.ThisUpdate)
               && CRLNumber.Equals(other.CRLNumber);
    }
    /// <inheritdoc />
    public override Int32 GetHashCode() {
        unchecked {
            Int32 hashCode = Version;
            hashCode = (hashCode * 397) ^ (Int32)Type;
            hashCode = (hashCode * 397) ^ IssuerName.GetHashCode();
            hashCode = (hashCode * 397) ^ ThisUpdate.GetHashCode();
            hashCode = (hashCode * 397) ^ CRLNumber.GetHashCode();
            return hashCode;
        }
    }
}