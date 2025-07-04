﻿#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a certificate policy qualifier as specified in the <see href="http://tools.ietf.org/html/rfc5280">RFC 5280</see>.
/// <para>Certificate policy qualifier may be either a URL to an online policy repository or textual policy information.</para>
/// </summary>
public class X509PolicyQualifier {
    /// <summary>
    /// Initializes a new instance of the <see cref="X509PolicyQualifier"/> class from a string that contains a URL
    /// to an online certificate policy repository.
    /// </summary>
    /// <param name="url">A string that contains URL information.</param>
    /// <exception cref="ArgumentNullException"><strong>url</strong> parameter is null.</exception>
    /// <exception cref="UriFormatException"><strong>url</strong> parameter doesn't represent well-formed <see cref="Uri"/>.</exception>
    public X509PolicyQualifier(String url) {
        if (String.IsNullOrEmpty(url)) {
            throw new ArgumentNullException(nameof(url));
        }
        InitializeUrl(url);
    }
    /// <summary>
    /// Initializes a new instance of the <see cref="X509PolicyQualifier"/> class from either or both notice reference
    /// and explicit notice text.
    /// </summary>
    /// <param name="noticeText">A string that contains brief policy information.</param>
    /// <param name="noticeRef">A string that contains brief information about organization name.</param>
    /// <exception cref="OverflowException">Input string has more than 200 character length.</exception>
    /// <exception cref="ArgumentNullException">
    /// Both, <strong>noticeText</strong> and <strong>noticeRef</strong> are null or empty.
    /// </exception>
    public X509PolicyQualifier(String noticeText, String noticeRef) {
        if (String.IsNullOrEmpty(noticeText) && String.IsNullOrEmpty(noticeRef)) {
            throw new ArgumentNullException(nameof(noticeText), "Both 'noticeText' and 'noticeRef' parameters cannot be null");
        }
        if (!String.IsNullOrEmpty(noticeText) && noticeText.Length > 200) {
            throw new OverflowException("Notice text cannot be larger than 200 characters.");
        }
        if (!String.IsNullOrEmpty(noticeRef) && noticeRef.Length > 200) {
            throw new OverflowException("Notice reference cannot be larger than 200 characters.");
        }
        InitializeNotice(noticeText, noticeRef);
    }
    /// <summary>
    /// Initializes a new instance of the <see cref="X509PolicyQualifier"/> class from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    public X509PolicyQualifier(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        m_decode(rawData);
    }

    /// <summary>
    /// Gets policy qualifier type.
    /// </summary>
    public X509PolicyQualifierType Type { get; private set; }
    /// <summary>
    /// Gets a URL to an online policy repository.
    /// </summary>
    public Uri? PolicyUrl { get; private set; }
    /// <summary>
    /// Gets a raw value of <see cref="PolicyUrl">CPS Pointer</see> property as a string.
    /// </summary>
    public String? PolicyUrlString { get; private set; }
    /// <summary>
    /// Gets an organization name associated with a qualifier.
    /// </summary>
    public String? NoticeReference { get; private set; }
    /// <summary>
    /// Gets an explicit notice text which is displayed in the certificate view UI.
    /// </summary>
    public String? NoticeText { get; private set; }
    /// <summary>
    /// Gets notice number in the collection of policy qualifiers. This property is set automatically
    /// when calling <see cref="X509PolicyQualifierCollection.Encode()">Encode</see> method on an
    /// <see cref="X509PolicyQualifierCollection"/> object.
    /// </summary>
    public Int32 NoticeNumber { get; internal set; }

    void InitializeUrl(String url) {
        Type = X509PolicyQualifierType.CpsUrl;
        PolicyUrl = new Uri(url);
    }
    void InitializeNotice(String noticeText, String noticeRef) {
        Type = X509PolicyQualifierType.UserNotice;
        NoticeReference = noticeRef;
        NoticeText = noticeText;
        NoticeNumber = 1;
    }
    void m_decode(Byte[] rawData) {
        Asn1Reader asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        asn.MoveNext();
        Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
        switch (oid.Value) {
            case "1.3.6.1.5.5.7.2.1":
                Type = X509PolicyQualifierType.CpsUrl;
                asn.MoveNext();
                PolicyUrlString = Encoding.UTF8.GetString(asn.GetPayload()).TrimEnd();
                try {
                    PolicyUrl = new Uri(PolicyUrlString);
                } catch { }
                break;
            case "1.3.6.1.5.5.7.2.2":
                Type = X509PolicyQualifierType.UserNotice;
                if (!asn.MoveNext()) { return; }
                if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
                asn.MoveNext();
                if (asn.Tag == 48) {
                    Int32 offset = asn.Offset;
                    asn.MoveNext();
                    NoticeReference = Asn1String.DecodeAnyString(asn.GetTagRawData(), [Asn1Type.IA5String, Asn1Type.VisibleString, Asn1Type.BMPString, Asn1Type.UTF8String]).Value;
                    asn.MoveNext();
                    asn.MoveNext();
                    NoticeNumber = (Int32)((Asn1Integer)asn.GetTagObject()).Value;
                    asn.Seek(offset);
                    if (asn.MoveNextSibling()) {
                        NoticeText = Asn1String.DecodeAnyString(asn.GetTagRawData(), [Asn1Type.IA5String, Asn1Type.VisibleString, Asn1Type.BMPString, Asn1Type.UTF8String]).Value;
                    }
                } else {
                    NoticeText = Asn1String.DecodeAnyString(asn.GetTagRawData(), [Asn1Type.IA5String, Asn1Type.VisibleString, Asn1Type.BMPString, Asn1Type.UTF8String]).Value;
                }
                break;
            default: m_reset(); return;
        }
    }
    void m_reset() {
        Type = X509PolicyQualifierType.Unknown;
        PolicyUrl = null;
        NoticeNumber = 0;
        NoticeReference = null;
        NoticeText = null;
    }

    static IEnumerable<Byte> EncodeString(String str) {
        try {
            return new Asn1VisibleString(str).GetRawData();
        } catch {
            return new Asn1UTF8String(str).GetRawData();
        }
    }

    /// <summary>
    /// Encodes current object to a ASN.1-encoded byte array.
    /// </summary>
    /// <returns>ASN.1-encoded byte array.</returns>
    /// <remarks>
    /// Explicit notice text is always encoded as a <strong>BMPString</strong>.
    /// <para>Notice reference is encoded in the following sequence: attempts to encode a string as a
    /// <strong>VisibleString</strong> and then as a <strong>BMPString</strong> if <strong>VisibleString</strong> fails.</para>
    /// </remarks>
    public Byte[] Encode() {
        switch (Type) {
            case X509PolicyQualifierType.CpsUrl:
                if (PolicyUrl?.AbsoluteUri == null) {
                    throw new ArgumentException("Policy qualifier URL cannot be null.");
                }
                return Asn1Builder.Create()
                    .AddObjectIdentifier(new Oid("1.3.6.1.5.5.7.2.1"))
                    .AddIA5String(PolicyUrl.AbsoluteUri)
                    .GetEncoded();
            case X509PolicyQualifierType.UserNotice:
                var refBuilder = Asn1Builder.Create();
                if (!String.IsNullOrEmpty(NoticeReference)) {
                    refBuilder.AddDerData(EncodeString(NoticeReference).ToArray())
                        .AddSequence(x => x.AddInteger(NoticeNumber))
                        .Encode();
                }
                if (!String.IsNullOrEmpty(NoticeText)) {
                    refBuilder.AddUTF8String(NoticeText);
                }
                return Asn1Builder.Create()
                    .AddObjectIdentifier(new Oid("1.3.6.1.5.5.7.2.2"))
                    .AddSequence(refBuilder.GetEncoded())
                    .GetEncoded();
            default: throw new ArgumentException("Cannot encode unsupported policy qualifier type.");
        }
    }
}