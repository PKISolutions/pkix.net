using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.Pkcs;
public static class Pkcs9AttributeObjectExtensions {
    /// <summary>
    /// Encodes current object to ASN.1-encoded byte array.
    /// </summary>
    /// <param name="attribute">An instance of <see cref="Pkcs9AttributeObject"/> to encode.</param>
    /// <returns>ASN.1-encoded byte array.</returns>
    public static Byte[] Encode(this Pkcs9AttributeObject attribute) {
        var list = new List<Byte>(Asn1Utils.Encode(attribute.RawData, 49));
        list.InsertRange(0, Asn1Utils.EncodeObjectIdentifier(attribute.Oid));
        return Asn1Utils.Encode(list.ToArray(), 48);
    }
    /// <summary>
    /// Returns a formatted version of the Abstract Syntax Notation One (ASN.1)-encoded data as a string.
    /// </summary>
    /// <param name="attribute">An instance of <see cref="Pkcs9AttributeObject"/> to format.</param>
    /// <param name="multiLine">
    /// <strong>True</strong> if the return string should contain carriage returns; otherwise, <strong>False</strong>
    /// </param>
    /// <returns>
    /// A formatted string that represents the Abstract Syntax Notation One (ASN.1)-encoded data
    /// </returns>
    /// <remarks>Use this method if you need to print Abstract Syntax Notation One (ASN.1)-encoded data or output the
    /// information to a text box. Use the <strong>multiLine</strong> parameter to control the layout of the output.</remarks>
    public static String FormatEx(this Pkcs9AttributeObject attribute, Boolean multiLine) {
        if (attribute.RawData != null && attribute.RawData.Length != 0) {
            var SB = new StringBuilder();
            var asn = new Asn1Reader(attribute.RawData);
            switch (attribute.Oid.Value) {
                // Content Type
                case "1.2.840.113549.1.9.3":
                    Oid value = Asn1Utils.DecodeObjectIdentifier(asn.GetRawData());
                    SB.Append("Content type (OID=1.2.840.113549.1.9.3): ");
                    if (multiLine) {
                        SB.Append(Environment.NewLine + "    " + value.Value);
                    } else {
                        SB.Append(value.Value);
                    }
                    if (!String.IsNullOrEmpty(value.FriendlyName)) {
                        SB.Append("(" + value.FriendlyName + ")");
                    }
                    break;
                // Message Digest
                case "1.2.840.113549.1.9.4":
                    SB.Append("Message Digest (OID=1.2.840.113549.1.9.4): ");
                    if (multiLine) {
                        SB.Append(Environment.NewLine + Asn1Utils.DecodeOctetString(asn.GetRawData()));
                    } else {
                        SB.Append(Asn1Utils.DecodeOctetString(asn.GetRawData()));
                    }
                    break;
                // Renewal certificate
                case "1.3.6.1.4.1.311.13.1":
                    var cert = new X509Certificate2(asn.GetRawData());
                    SB.Append("Renewal Certificate (OID=1.3.6.1.4.1.311.13.1): ");
                    if (multiLine) {
                        SB.Append(Environment.NewLine + "    " + cert.ToString().Replace("\r\n", "\r\n    "));
                    } else {
                        SB.Append(cert.ToString().Replace("\r\n", " ").Replace("   ", " ").Replace("  ", ", "));
                    }
                    break;
                //  Enrollment Name Value Pair
                case "1.3.6.1.4.1.311.13.2.1":
                    asn.MoveNext();
                    SB.Append("Enrollment Name Value Pair (OID=1.3.6.1.4.1.311.13.2.1): ");
                    if (multiLine) {
                        SB.Append(Environment.NewLine + "    ");
                    }
                    SB.Append(Encoding.BigEndianUnicode.GetString(asn.GetPayload()) + "=");
                    asn.MoveNext();
                    SB.Append(Encoding.BigEndianUnicode.GetString(asn.GetPayload()));
                    if (multiLine) { SB.Append(Environment.NewLine); }
                    break;
                // CSP Info
                case "1.3.6.1.4.1.311.13.2.2":
                    asn.MoveNext();
                    SB.Append("CSP Info (OID=1.3.6.1.4.1.311.13.2.2): ");
                    if (multiLine) { SB.Append(Environment.NewLine + "    "); }
                    if (asn.Tag == (Int32)Asn1Type.INTEGER) {
                        SB.Append("KeySpec: " + asn.GetPayload()[0]);
                        asn.MoveNext();
                    }
                    if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                    if (asn.Tag == (Int32)Asn1Type.BMPString) {
                        SB.Append("Provider: " + Encoding.BigEndianUnicode.GetString(asn.GetPayload()));
                        asn.MoveNext();
                    }
                    if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                    if (asn.Tag == (Int32)Asn1Type.BIT_STRING) {
                        SB.Append("Signature unused bits: " + asn.GetPayload()[0]);
                    }
                    if (multiLine) { SB.Append(Environment.NewLine); }
                    break;
                //OS version
                case "1.3.6.1.4.1.311.13.2.3":
                    SB.Append("OS Version (OID=1.3.6.1.4.1.311.13.2.3): " + Asn1Utils.DecodeIA5String(asn.GetTagRawData()));
                    if (multiLine) { SB.Append(Environment.NewLine); }
                    break;
                // client info
                case "1.3.6.1.4.1.311.21.20":
                    asn.MoveNext();
                    SB.Append("Client Info (OID=1.3.6.1.4.1.311.21.20): ");
                    if (multiLine) { SB.Append(Environment.NewLine + "    "); }
                    if (asn.Tag == (Int32)Asn1Type.INTEGER) {
                        Int64 id = Asn1Utils.DecodeInteger(asn.GetTagRawData());
                        SB.Append("Client ID: " + (EnrollmentClientIdType)id + " (" + id + ")");
                        asn.MoveNext();
                    }
                    if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                    if (asn.Tag == (Int32)Asn1Type.UTF8String) {
                        SB.Append("Computer name: " + Asn1Utils.DecodeUTF8String(asn.GetTagRawData()));
                        if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                        asn.MoveNext();
                        SB.Append("User name: " + Asn1Utils.DecodeUTF8String(asn.GetTagRawData()));
                        if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                        asn.MoveNext();
                        SB.Append("Process name: " + Asn1Utils.DecodeUTF8String(asn.GetTagRawData()));
                        if (multiLine) { SB.Append(Environment.NewLine); }
                    }
                    break;
                // szOID_NT_PRINCIPAL_NAME
                case "1.3.6.1.4.1.311.20.2.3":
                    if (asn.Tag == (Byte)Asn1Type.UTF8String) {
                        SB.Append("User Principal Name (OID=1.3.6.1.4.1.311.20.2.3): " + Asn1Utils.DecodeUTF8String(asn.GetTagRawData()));
                        if (multiLine) { SB.Append(Environment.NewLine); }
                    }
                    break;
                // szOID_NTDS_REPLICATION
                case "1.3.6.1.4.1.311.25.1":
                    if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                        SB.Append("NTDS Replication GUID (OID=1.3.6.1.4.1.311.25.1): " + new Guid(asn.GetPayload()));
                        if (multiLine) { SB.Append(Environment.NewLine); }
                    }
                    break;
                #region PropIDs
                // CERT_SHA1_HASH_PROP_ID
                case "1.3.6.1.4.1.311.10.11.3":
                    if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                        SB.Append("SHA1 hash (OID=1.3.6.1.4.1.311.10.11.3): " + Asn1Utils.DecodeOctetString(asn.GetTagRawData()));
                        if (multiLine) { SB.Append(Environment.NewLine); }
                    }
                    break;
                // CERT_MD5_HASH_PROP_ID
                case "1.3.6.1.4.1.311.10.11.4":
                    if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                        SB.Append("SHA1 hash (OID=1.3.6.1.4.1.311.10.11.4): " + Asn1Utils.DecodeOctetString(asn.GetTagRawData()));
                        if (multiLine) { SB.Append(Environment.NewLine); }
                    }
                    break;
                // CERT_ENHKEY_USAGE_PROP_ID
                case "1.3.6.1.4.1.311.10.11.9":
                    if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                        asn.MoveNext();
                        asn.MoveNext();
                        SB.Append("Enhanced Key Usages (OID=1.3.6.1.4.1.311.10.11.9): ");
                        if (multiLine) { SB.Append(Environment.NewLine + "    "); }
                        do {
                            if (Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData()).FriendlyName != null) {
                                SB.Append(Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData()).Value + " (" + Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData()).FriendlyName + ") ");
                            } else {
                                SB.Append(Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData()).Value);
                            }
                            if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                        } while (asn.MoveNext());
                    }
                    break;
                // CERT_FRIENDLY_NAME_PROP_ID
                case "1.3.6.1.4.1.311.10.11.11":
                    if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                        SB.Append("Friendly name (OID=1.3.6.1.4.1.311.10.11.11): " + Encoding.Unicode.GetString(asn.GetPayload()));
                        if (multiLine) { SB.Append(Environment.NewLine); }
                    }
                    break;
                // CERT_KEY_IDENTIFIER_PROP_ID
                case "1.3.6.1.4.1.311.10.11.20":
                    if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                        SB.Append("Subject Key Identifier (OID=1.3.6.1.4.1.311.10.11.20): " + Asn1Utils.DecodeOctetString(asn.GetTagRawData()));
                        if (multiLine) { SB.Append(Environment.NewLine); }
                    }
                    break;
                // CERT_SUBJECT_NAME_MD5_HASH_PROP_ID
                case "1.3.6.1.4.1.311.10.11.29":
                    if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                        SB.Append("Subject name MD5 hash (OID=1.3.6.1.4.1.311.10.11.29): " + Asn1Utils.DecodeOctetString(asn.GetTagRawData()));
                        if (multiLine) { SB.Append(Environment.NewLine); }
                    }
                    break;
                #endregion
                default:
                    SB.Append("Unknown attribute (OID=" + attribute.Oid.Value);
                    if (!String.IsNullOrEmpty(attribute.Oid.FriendlyName)) {
                        SB.Append(" (" + attribute.Oid.FriendlyName + ")");
                    }
                    SB.Append("): ");
                    if (multiLine) {
                        String tempString = AsnFormatter.BinaryToString(attribute.RawData, EncodingType.HexAsciiAddress);
                        SB.Append(tempString.Replace("\r\n", "\r\n    ") + Environment.NewLine);
                        SB.Append(Environment.NewLine);
                    } else {
                        SB.Append(AsnFormatter.BinaryToString(attribute.RawData) + Environment.NewLine);
                    }
                    break;
            }
            return SB.ToString();
        }
        return attribute.Format(multiLine);
    }
}
