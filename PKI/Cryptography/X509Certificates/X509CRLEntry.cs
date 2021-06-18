using System.Collections;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Text;
using PKI.Exceptions;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a CRL entry of certificate revocation list that contains information about revoked certificate.
    /// </summary>
    /// <remarks>This class do not expose any public constructor.</remarks>
    public sealed class X509CRLEntry {
        /// <summary>
        /// Initializes a new instance of the <strong>X509CRLEntry</strong> class from a serial number, revocation date and revocation reason code.
        /// </summary>
        /// <param name="serialNumber">
        /// Specifies the revoked certificate serial number. Serial number must be a hex string. It may be lower/upper case and may contain single space
        /// between octets.
        /// </param>
        /// <param name="revocationDate">
        /// Specifies the date and time when certificate is considered explicitly untrusted (revoked). If the parameter is null, a current date and time
        /// is used.
        /// </param>
        /// <param name="reasonCode">
        /// Specifies the revocation reason. The value can be one of specified in the <see cref="ReasonCode"/>, except: <strong>Hold Certificate</strong>
        /// and <strong>Release From Hold</strong>. Default parameter value is <strong>Unspecified</strong>.
        /// </param>
        /// <exception cref="ArgumentNullException">The <strong>serialNumber</strong> parameter is null reference or empty string.</exception>
        /// <exception cref="ArgumentException">The <strong>reasonCode</strong> contains invalid reason code.</exception>
        public X509CRLEntry(String serialNumber, DateTime? revocationDate = null, Int32 reasonCode = 0) {
            if (String.IsNullOrEmpty(serialNumber)) {
                throw new ArgumentNullException(nameof(serialNumber));
            }
            if (revocationDate == null) {
                revocationDate = DateTime.Now;
            }

            encode(serialNumber, revocationDate.Value, reasonCode);
        }
        /// <summary>
        /// Initializes a new instance of the <strong>X509CRLEntry</strong> class from a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="ArgumentNullException">The <strong>rawData</strong> parameter is null reference.</exception>
        /// <exception cref="InvalidDataException">The data do not contains valid CRL entry structure.</exception>
        public X509CRLEntry(Byte[] rawData) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            decode(new Asn1Reader(rawData));
        }
        public X509CRLEntry(Asn1Reader asn) {
            if (asn == null) {
                throw new ArgumentNullException(nameof(asn));
            }
            decode(asn);
        }

        /// <summary>
        /// Gets the serial number of the revoked certificate.
        /// </summary>
        public String SerialNumber { get; private set; }
        /// <summary>
        /// Gets the date and time when certificate was revoked by an issuer.
        /// </summary>
        public DateTime RevocationDate { get; private set; }
        /// <summary>
        /// Gets the revocation reason code. The possible codes and their values are:
        /// <list type="table">
        ///		<listheader>
        ///			<term>Revocation code</term>
        ///			<description>Code definition.</description>
        ///		</listheader>
        ///		<item>
        ///			<term>0</term>
        ///			<description><strong>Unspecified</strong> - the certificate was revoked due to a reason that is not referenced in the table.</description>
        ///		</item>
        ///		<item>
        ///			<term>1</term>
        ///			<description><strong>Key Compromise</strong> - the certificate's private key was compromised or disclosed to a unauthorized person.
        ///			This code is used for end entity certificates.</description>
        ///		</item>
        ///		<item>
        ///			<term>2</term>
        ///			<description><strong>CA Compromise</strong> - the CA certificate's private key was compromised or disclosed to a unauthorized person.
        ///			This code is used for CA certificates.</description>
        ///		</item>
        ///		<item>
        ///			<term>3</term>
        ///			<description><strong>Change Of Affiliation</strong> - the certificate holder changed his/her position or role that do not allow
        ///			current certificate usage.</description>
        ///		</item>
        ///		<item>
        ///			<term>4</term>
        ///			<description><strong>Superseded</strong> - the certificate was revoked because it is superseded by a new certificate.</description>
        ///		</item>
        ///		<item>
        ///			<term>5</term>
        ///			<description><strong>Cease Of Operation</strong> - the certificate holder do no longer perform the role. For example, an employee
        ///			leaves a organization, or server is decommissioned.</description>
        ///		</item>
        ///		<item>
        ///			<term>6</term>
        ///			<description><strong>Hold Certificate</strong> - the certificate is revoked for a time (not permanently) and it is possible to
        ///			"unrevoke" the certificate further. This code should not be used, because it is impossible to determine whether the certificate
        ///			was invalid at certain date.</description>
        ///		</item>
        ///		<item>
        ///			<term>7</term>
        ///			<description><strong>Privilege Withdrawn</strong> - the certificate holder do not have required privileges to use the certificate.</description>
        ///		</item>
        ///		<item>
        ///			<term>8</term>
        ///			<description><strong>Release From Hold</strong> - the certificate is removed from <strong>Hold Certificate</strong> state and
        ///			will be removed from CRL.</description>
        ///		</item>
        ///		<item>
        ///			<term>10</term>
        ///			<description><strong>Authorization Authority Compromise</strong> - the authority that performs authorization tasks is compromised/disclosed.</description>
        ///		</item>
        /// </list>
        /// </summary>
        /// <remarks>Revocation reason textual meaning is provided in the <see cref="ReasonMessage"/> property description.</remarks>
        public Int32 ReasonCode { get; private set; }
        /// <summary>
        /// Gets the textual representation of RevocationCode. See <see cref="ReasonCode"/> for the list of possible values
        /// and code meanings.
        /// </summary>
        public String ReasonMessage => getReasonText(ReasonCode);

        /// <summary>
        /// Gets the ASN.1-encoded byte array.
        /// </summary>
        [Obsolete("Use 'Encode()' method instead.")]
        public Byte[] RawData { get; private set; }

        void encode(String serialNumber, DateTime revocationDate, Int32 reasonCode) {
            if (reasonCode < 0 || reasonCode > 10) {
                throw new ArgumentException("Revocation reason code is incorrect.");
            }
            if (serialNumber.Length % 2 == 1) {
                serialNumber = "0" + serialNumber;
            }
            SerialNumber = serialNumber.Replace(" ", null).ToLower();
            RevocationDate = revocationDate;
            ReasonCode = reasonCode;
            RawData = Encode();
        }

        void decode(Asn1Reader asn) {
            if (asn.Tag != 48) {
                throw new Asn1InvalidTagException(asn.Offset);
            }
            RawData = asn.GetTagRawData();
            Int32 offset = asn.Offset;
            asn.MoveNext();
            SerialNumber = Asn1Utils.DecodeInteger(asn.GetTagRawData(), true);
            asn.MoveNextAndExpectTags(Asn1Type.UTCTime, Asn1Type.GeneralizedTime);
            switch (asn.Tag) {
                case (Byte)Asn1Type.UTCTime:
                    RevocationDate = new Asn1UtcTime(asn.GetTagRawData()).Value;
                    break;
                case (Byte)Asn1Type.GeneralizedTime:
                    RevocationDate = Asn1Utils.DecodeGeneralizedTime(asn.GetTagRawData());
                    break;
            }
            if (asn.MoveNextSibling()) {
                // use high-performant extension decoder instead of generic one.
                // Since CRLs may store a hundreds of thousands entries, this is
                // pretty reasonable to save loops whenever possible.
                readCrlReasonCode(asn);
            }
            asn.Seek(offset);
        }
        void readCrlReasonCode(Asn1Reader asn) {
            if (asn.Tag != 48) {
                return;
            }
            asn.MoveNext();
            do {
                Int32 offset = asn.Offset;
                asn.MoveNextAndExpectTags(Asn1Type.OBJECT_IDENTIFIER);
                var oid = new Asn1ObjectIdentifier(asn).Value;
                if (oid.Value == X509ExtensionOid.CRLReasonCode) {
                    asn.MoveNext();
                    if (asn.Tag == (Byte)Asn1Type.BOOLEAN) {
                        asn.MoveNext();
                    }
                    if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                        asn.MoveNext();
                        if (asn.PayloadLength > 0) {
                            ReasonCode = asn[asn.PayloadStartOffset];
                            break;
                        }
                    }
                }
                asn.Seek(offset);
            } while (asn.MoveNextSibling());
        }
        static String getReasonText(Int32 code) {
            var Reasons = new Hashtable {
                {0, "Unspecified"},
                {1, "Key compromise"},
                {2, "CA Compromise"},
                {3, "Change Of Affiliation"},
                {4, "Superseded"},
                {5, "Cease Of Operation"},
                {6, "Hold Certificate"},
                {7, "Privilege Withdrawn"},
                {8, "Release From Hold"},
                {10, "Authorization Authority Compromise"}
            };
            return (String)Reasons[code];
        }

        /// <summary>
        /// Gets textual information about revoked certificate. An output contains certificate serial number and revocation date.
        /// </summary>
        /// <returns>Information about revoked certificate</returns>
        public override String ToString() {
            StringBuilder SB = new StringBuilder();
            SB.Append("Serial number: " + SerialNumber + " revoked at: " + RevocationDate);
            return SB.ToString();
        }
        /// <summary>
        /// Encodes revocation entry to a ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array</returns>
        public Byte[] Encode() {
            if (String.IsNullOrEmpty(SerialNumber)) {
                throw new UninitializedObjectException();
            }
            // TODO:  verify this
            Asn1Builder builder = Asn1Builder.Create()
                .AddInteger(BigInteger.Parse(SerialNumber, NumberStyles.AllowHexSpecifier))
                .AddRfcDateTime(RevocationDate);
            if (ReasonCode > 0) {
                builder.AddSequence(x =>
                                        x.AddSequence(y => {
                                            y.AddObjectIdentifier(new Oid(X509ExtensionOid.CRLReasonCode));
                                            return y.AddOctetString(z => z.AddEnumerated((UInt64)ReasonCode));
                                        }));
            }
            return builder.GetEncoded();
        }
        /// <summary>
        /// Compares two <see cref="X509CRLEntry"/> objects for equality.
        /// </summary>
        /// <param name="obj">An <see cref="X509CRLEntry"/> object to compare to the current object. </param>
        /// <returns><strong>True</strong> if the current <see cref="X509CRLEntry"/> object is equal to the object specified
        /// by the other parameter; otherwise, <strong>False</strong>.</returns>
        /// <remarks>Two objects are considered equal if they are <strong>X509CRLEntry</strong> objects and they have the same
        /// serial number.</remarks>
        public override Boolean Equals(Object obj) {
            if (obj is null) { return false; }
            if (ReferenceEquals(this, obj)) { return true; }
            return obj.GetType() == GetType() && Equals((X509CRLEntry)obj);
        }
        Boolean Equals(X509CRLEntry other) {
            return String.Equals(SerialNumber, other.SerialNumber);
        }
        /// <inheritdoc />
        public override Int32 GetHashCode() {
            unchecked {
                Int32 hashCode = SerialNumber?.GetHashCode() ?? 0;
                hashCode = (hashCode * 397) ^ RevocationDate.GetHashCode();
                hashCode = (hashCode * 397) ^ ReasonCode;
                return hashCode;
            }
        }
    }
}
