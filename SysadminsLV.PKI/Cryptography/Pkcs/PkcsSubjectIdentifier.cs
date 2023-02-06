using System;
using System.Collections.Generic;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Cryptography.Pkcs {
    /// <summary>
    /// The <strong>SubjectIdentifier2</strong> class defines the type of the identifier of a subject, such as
    /// a <see cref="SysadminsLV.PKI.Cryptography.Pkcs.PkcsSignerInfo"/>. The subject can be identified by the certificate issuer and serial number
    /// or the subject key.
    /// </summary>
    /// <remarks>This class is a replacement for for a .NET native <see cref="SubjectIdentifier"/> class.</remarks>
    public sealed class PkcsSubjectIdentifier {
        readonly List<Byte> _rawData = new();

        /// <summary>
        /// Initializes a new instance of <strong>PkcsSubjectIdentifier</strong> class using signer certificate and type how this certificate
        /// is referenced in signer information of <see cref="SysadminsLV.PKI.Cryptography.Pkcs.PkcsSignerInfo"/> object.
        /// </summary>
        /// <param name="certificate">
        /// A certificate used to sign data.
        /// </param>
        /// <param name="subjectType">A type how presented certificate will be referenced in <see cref="SysadminsLV.PKI.Cryptography.Pkcs.PkcsSignerInfo"/>.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>certificate</strong> parameter is null.
        /// </exception>
        public PkcsSubjectIdentifier(X509Certificate2 certificate, SubjectIdentifierType subjectType) {
            if (certificate == null) {
                throw new ArgumentNullException(nameof(certificate));
            }
            Type = subjectType;
            encode(certificate);
        }
        /// <summary>
        ///     Initializes a new instance of <strong>SubjectIdentifier2</strong> class from ASN.1-encoded byte array that represents encoded
        ///     Subject Identifier structure.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>rawData</strong> parameter is <strong>null</strong>.
        /// </exception>
        public PkcsSubjectIdentifier(Byte[] rawData) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            decode(rawData);
        }

        /// <summary>
        /// Gets the type of the of subject identifier. The subject can be identified by the certificate issuer and
        /// serial number or the subject key.
        /// <para>
        /// The following table displays mappings between subject identifier type and object type stored in the
        /// <see cref="Value"/> property:
        /// <list type="table">
        ///		<listheader>
        ///			<term>Identifier type</term>
        ///			<description>Object type</description>
        ///		</listheader>
        ///		<item>
        ///			<term><strong>IssuerAndSerialNumber</strong></term>
        ///			<description>An instance of <see cref="X509IssuerSerial"/> class.</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>SubjectKeyIdentifier</strong></term>
        ///			<description>
        ///				A string that represents subject key identifier value (cryptographic hash calculated
        ///				over a public key).
        ///			</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>Sha1Hash</strong></term>
        ///			<description>A SHA1 hash of the certificate to be used as a unique identifier of the certificate.</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>Unknown</strong></term>
        ///			<description>NULL</description>
        ///		</item>
        /// </list>
        /// </para>
        /// </summary>
        public SubjectIdentifierType Type { get; private set; }
        /// <summary>
        /// Contains the value of the subject identifier. Object type and it's description depends on <see cref="Type"/>
        /// property value.
        /// <para>
        /// The following table displays mappings between subject identifier type and object type stored in the
        /// property:
        /// <list type="table">
        ///		<listheader>
        ///			<term>Identifier type</term>
        ///			<description>Object type</description>
        ///		</listheader>
        ///		<item>
        ///			<term><strong>IssuerAndSerialNumber</strong></term>
        ///			<description>An instance of <see cref="X509IssuerSerial"/> class.</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>SubjectKeyIdentifier</strong></term>
        ///			<description>
        ///				A string that represents subject key identifier value (cryptographic hash calculated
        ///				over a public key).
        ///			</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>NoSignature</strong></term>
        ///			<description>A string that contains hash value of external message.</description>
        ///		</item>
        ///		<item>
        ///			<term><strong>Unknown</strong></term>
        ///			<description>NULL.</description>
        ///		</item>
        /// </list>
        /// </para>
        /// </summary>
        public Object Value { get; private set; }
        /// <summary>
        /// Gets the raw data associated with the current object.
        /// </summary>
        public Byte[] RawData => _rawData.ToArray();

        void encode(X509Certificate2 certificate) {
            switch (Type) {
                case SubjectIdentifierType.SubjectKeyIdentifier:
                    if (certificate.Extensions[X509ExtensionOid.SubjectKeyIdentifier] is X509SubjectKeyIdentifierExtension ski) {
                        Value = ski.SubjectKeyIdentifier;
                    } else {
                        throw new ArgumentException("Specified certificate does not contain X.509 Subject Key Identifier extension.");
                    }
                    break;
                case SubjectIdentifierType.IssuerAndSerialNumber:
                    Value = new X509IssuerSerial(certificate.SubjectName, certificate.SerialNumber);
                    break;
                default:
                    throw new ArgumentException("Invalid CMS issuer identifier type.");
            }
        }
        void decode(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            switch (asn.Tag) {
                case 48:
                    Type = SubjectIdentifierType.IssuerAndSerialNumber;
                    Value = new X509IssuerSerial(asn.GetTagRawData());
                    break;
                case 0x80:
                    Type = SubjectIdentifierType.SubjectKeyIdentifier;
                    Value = AsnFormatter.BinaryToString(asn, EncodingType.HexRaw, EncodingFormat.NOCRLF);
                    break;
                default: throw new ArgumentException("Invalid CMS issuer identifier type.");
            }
            _rawData.AddRange(rawData);
        }

        /// <summary>
        /// Encodes current object to an ASN.1 format.
        /// </summary>
        /// <returns>ASN.1-encoded byte array that represents current object.</returns>
        public Byte[] Encode() {
            var retValue = new List<Byte>();
            switch (Type) {
                case SubjectIdentifierType.IssuerAndSerialNumber:
                    retValue.AddRange(((X509IssuerSerial)Value).RawData);
                    break;
                case SubjectIdentifierType.SubjectKeyIdentifier:
                    retValue.AddRange(Asn1Utils.Encode(AsnFormatter.StringToBinary(Value.ToString(), EncodingType.HexRaw), 0x80));
                    break;
                default:
                    throw new ArgumentException("Invalid CMS issuer identifier type.");
            }
            return retValue.ToArray();
        }
    }
}
