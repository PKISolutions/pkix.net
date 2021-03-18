using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents Authority Key Identifier extension. The authority key identifier extension provides a means of
    /// identifying the public key corresponding to the private key used to sign a certificate.
    /// </summary>
    public sealed class X509AuthorityKeyIdentifierExtension : X509Extension {
        readonly Oid _oid = new Oid(X509ExtensionOid.AuthorityKeyIdentifier);

        /// <summary>
        /// Intitializes a new instance of <strong>X509AuthorityKeyIdentifierExtension</strong> class from
        /// ASN.1-encoded AKI extension value and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="aki">An ASN.1-encoded Authority Key Identifier extension value.</param>
        /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>aki</strong> parameter is null;
        /// </exception>
        public X509AuthorityKeyIdentifierExtension(AsnEncodedData aki, Boolean critical)
            : base(X509ExtensionOid.AuthorityKeyIdentifier, aki.RawData, critical) {
            if (aki == null) { throw new ArgumentNullException(nameof(aki)); }
            m_decode(aki.RawData);
        }
        /// <summary>
        /// Intitializes a new instance of <strong>X509AuthorityKeyIdentifierExtension</strong> class from
        /// a key identifier value and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="keyIdentifier">Must be a hex string that represents hash value.</param>
        /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>keyIdentifier</strong> value is null or empty.
        /// </exception>
        public X509AuthorityKeyIdentifierExtension(String keyIdentifier, Boolean critical) {
            if (String.IsNullOrEmpty(keyIdentifier)) { throw new ArgumentNullException(nameof(keyIdentifier)); }
            initializeFromKeyId(keyIdentifier, critical);
        }
        /// <summary>
        /// Intitializes a new instance of <strong>X509AuthorityKeyIdentifierExtension</strong> class from
        /// an issuer certificate, extension generation flags an a value that identifies whether the extension
        /// is critical.
        /// </summary>
        /// <param name="issuer">Issuer certificate which is used to construct the AKI extension.</param>
        /// <param name="flags">
        /// Indicates which issuer components are included in the AKI extension. If the value is zero (None),
        /// then default <strong>KeyIdentifier</strong> component will be included.
        /// </param>
        /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>issuer</strong> parameter is null.
        /// </exception>
        /// <remarks>
        /// If <strong>flags</strong> parameter contains <strong>AlternativeNames</strong> and issuer certificate
        /// does not contain Subject Alternative Names (SAN) extension, <strong>AlternativeNames</strong> flags
        /// is ignored. If <strong>AlternativeNames</strong> is the only flag, and SAN extension is missing, only
        /// <strong>KeyIdentifier</strong> component will be included.
        /// </remarks>
        public X509AuthorityKeyIdentifierExtension(X509Certificate2 issuer, AuthorityKeyIdentifierFlags flags, Boolean critical) {
            if (issuer == null || IntPtr.Zero.Equals(issuer.Handle)) { throw new ArgumentNullException(nameof(issuer)); }
            if (flags == AuthorityKeyIdentifierFlags.AlternativeNames && issuer.Extensions[X509ExtensionOid.SubjectAlternativeNames] == null) {
                flags = AuthorityKeyIdentifierFlags.KeyIdentifier;
            }
            if (flags == AuthorityKeyIdentifierFlags.None) {
                flags |= AuthorityKeyIdentifierFlags.KeyIdentifier;
            }
            initializeFromCert(issuer, flags, critical);
        }

        void initializeFromCert(X509Certificate2 issuer, AuthorityKeyIdentifierFlags flags, Boolean critical) {
            Oid = _oid;
            Critical = critical;
            IncludedComponents = AuthorityKeyIdentifierFlags.None;
            // TODO rawData is not used
            List<Byte> rawData = new List<Byte>();
            if ((flags & AuthorityKeyIdentifierFlags.KeyIdentifier) > 0) {
                using (var hasher = SHA1.Create()) {
                    var hashbytes = hasher.ComputeHash(issuer.PublicKey.EncodedKeyValue.RawData);
                    KeyIdentifier = AsnFormatter.BinaryToString(hashbytes, EncodingType.HexRaw, EncodingFormat.NOCRLF);
                    rawData.AddRange(Asn1Utils.Encode(hashbytes, 0x80));
                }
                IncludedComponents |= AuthorityKeyIdentifierFlags.KeyIdentifier;
            }
            if ((flags & AuthorityKeyIdentifierFlags.AlternativeNames) > 0) {
                X509Extension san = issuer.Extensions[X509ExtensionOid.SubjectAlternativeNames];
                Debug.Assert(san != null, "san != null");
                AsnEncodedData encoded = new AsnEncodedData(san.RawData);
                var sanExt = new X509SubjectAlternativeNamesExtension(encoded, false);
                IssuerNames = sanExt.AlternativeNames;
                IssuerNames.Close();
                Asn1Reader asn = new Asn1Reader(san.RawData);
                rawData.AddRange(Asn1Utils.Encode(asn.GetPayload(), 0x81));
                IncludedComponents |= AuthorityKeyIdentifierFlags.AlternativeNames;
            }
            if ((flags & AuthorityKeyIdentifierFlags.SerialNumber) > 0) {
                SerialNumber = issuer.SerialNumber;
                rawData.AddRange(Asn1Utils.Encode(issuer.GetSerialNumber().Reverse().ToArray(), 0x82));
                IncludedComponents |= AuthorityKeyIdentifierFlags.SerialNumber;
            }
            RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        void initializeFromKeyId(String keyId, Boolean critical) {
            Oid = _oid;
            Critical = critical;
            IncludedComponents = AuthorityKeyIdentifierFlags.KeyIdentifier;

            Byte[] keyIdBytes = AsnFormatter.StringToBinary(keyId);
            KeyIdentifier = AsnFormatter.BinaryToString(keyIdBytes, EncodingType.HexRaw, EncodingFormat.NOCRLF);
            RawData = Asn1Utils.Encode(AsnFormatter.StringToBinary(keyId, EncodingType.Hex), 0x80);
            RawData = Asn1Utils.Encode(RawData, 48);
        }
        void m_decode(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
            asn.MoveNext();
            IncludedComponents = AuthorityKeyIdentifierFlags.None;
            do {
                switch (asn.Tag) {
                    case 0x80:
                        KeyIdentifier = AsnFormatter.BinaryToString(asn.GetPayload(), EncodingType.HexRaw, EncodingFormat.NOCRLF);
                        IncludedComponents |= AuthorityKeyIdentifierFlags.KeyIdentifier;
                        break;
                    case 0xa1:
                        IssuerNames = new X509AlternativeNameCollection();
                        var bytes = Asn1Utils.Encode(asn.GetPayload(), 48);
                        IssuerNames.Decode(bytes);
                        IssuerNames.Close();
                        IncludedComponents |= AuthorityKeyIdentifierFlags.AlternativeNames;
                        break;
                    case 0x82:
                        SerialNumber = AsnFormatter.BinaryToString(asn.GetPayload());
                        IncludedComponents |= AuthorityKeyIdentifierFlags.SerialNumber;
                        break;
                }
            } while (asn.MoveNextCurrentLevel());
        }

        /// <summary>
        /// Indicates which components are included in the Authority Key Identifier extension.
        /// </summary>
        public AuthorityKeyIdentifierFlags IncludedComponents { get; private set; }
        /// <summary>
        /// Gets an octet string of the KeyIdientifier component. May be null.
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
    }
}
