using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.Pkcs {
    /// <summary>
    /// Represents the <strong>X509IssuerSerial</strong> element of an XML digital signature.
    /// </summary>
    /// <remarks>
    /// This class is a replacement for a .NET native <see href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.x509issuerserial.aspx">X509IssuerSerial</see> structure.
    /// </remarks>
    public sealed class X509IssuerSerial {
        readonly List<Byte> _rawData = new();
        /// <param name="issuer">An <see cref="X500DistinguishedName"/> object that represents issuer name.</param>
        /// <param name="serialNumber">A string that contains issuer certificate's serial number.</param>
        /// <exception cref="ArgumentNullException">
        ///		<strong>issuer</strong> and/or <strong>serialNumber</strong> parameters are null or empty.
        /// </exception>
        public X509IssuerSerial(X500DistinguishedName issuer, String serialNumber) {
            IssuerName = issuer ?? throw new ArgumentNullException(nameof(issuer));
            SerialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
            encode();
        }
        /// <summary>
        /// Initializes a new instance of <strong>X509IssuerSerial</strong> from ASN.1-encoded byte array that
        /// contains issuer information.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>rawData</strong> parameter is null.
        /// </exception>
        public X509IssuerSerial(Byte[] rawData) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            decode(rawData);
        }

        /// <summary>
        /// Gets or sets an X.509 certificate issuer's distinguished name.
        /// </summary>
        public X500DistinguishedName IssuerName { get; private set; }
        /// <summary>
        /// Gets an X.509 certificate issuer's distinguished name in a string format.
        /// </summary>
        public String Issuer => IssuerName.Name;

        /// <summary>
        /// Gets or sets an X.509 certificate issuer's serial number.
        /// </summary>
        public String SerialNumber { get; private set; }
        /// <summary>
        /// Gets ASN.1-encoded byte array that represents current object.
        /// </summary>
        public Byte[] RawData => _rawData.ToArray();

        void decode(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            asn.MoveNext();
            IssuerName = new X500DistinguishedName(asn.GetTagRawData());
            asn.MoveNextSiblingAndExpectTags((Byte)Asn1Type.INTEGER);
            SerialNumber = AsnFormatter.BinaryToString(asn);
            _rawData.AddRange(rawData);
        }
        void encode() {
            var rawData = new List<Byte>(IssuerName.RawData);
            rawData.AddRange(Asn1Utils.Encode(AsnFormatter.StringToBinary(SerialNumber, EncodingType.HexRaw), (Byte)Asn1Type.INTEGER));
            _rawData.AddRange(Asn1Utils.Encode(rawData.ToArray(), 48));
        }
    }
}
