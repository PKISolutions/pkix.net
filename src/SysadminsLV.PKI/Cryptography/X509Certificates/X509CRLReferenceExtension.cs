﻿using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Defines the <strong>id-pkix-ocsp-crl</strong> extension (defined in <see href="http://tools.ietf.org/html/rfc2560">RFC2560</see>).
/// This class cannot be inherited.
/// </summary>
/// <remarks>The class do not expose public constructors.</remarks>
public sealed class X509CRLReferenceExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.OcspCRLReference, "OCSP CRL Reference");

    X509CRLReferenceExtension(Byte[] rawData, Boolean critical) : base(_oid, rawData, critical) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        m_decode(rawData);
    }

    /// <summary>
    /// Initializes a new instance of the <strong>X509CRLReferenceExtension</strong> class.
    /// </summary>
    public X509CRLReferenceExtension() { Oid = _oid; }
    /// <summary>
    /// Initializes a new instance of the <strong>X509CRLReferenceExtension</strong> class using an
    /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
    /// </summary>
    /// <param name="value">The encoded data to use to create the extension.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    /// <exception cref="ArgumentException">
    /// The data in the <strong>value</strong> parameter is not valid extension value.
    /// </exception>
    public X509CRLReferenceExtension(AsnEncodedData value, Boolean critical) :
        this (value.RawData, critical) { }
    /// <summary>
    /// Initializes a new instance of the <strong>X509CRLReferenceExtension</strong> class using a
    /// CRL reference URL, CRL reference number and <see cref="X509CRL2.ThisUpdate">ThisUpdate</see>
    /// value of the referenced CRL that identifies extension settings.
    /// </summary>
    /// <param name="url">A CRL reference URL.</param>
    /// <param name="crlNumber">A CRL number that is specified in the hexadecimal format.</param>
    /// <param name="thisUpdate"><see cref="X509CRL2.ThisUpdate">ThisUpdate</see> value of the referenced CRL</param>
    /// <exception cref="ArgumentException">
    /// CRL reference number is not in the hexadecimal format.
    /// </exception>
    public X509CRLReferenceExtension(String url, String crlNumber, DateTime thisUpdate) {
        if (url == null) {
            throw new ArgumentNullException(nameof(url));
        }
        if (crlNumber == null) {
            throw new ArgumentNullException(nameof(crlNumber));
        }

        if (!Regex.IsMatch(crlNumber, @"\A\b[0-9a-fA-F]+\b\Z")) {
            throw new ArgumentException("The parameter is incorrect");
        }
        m_initialize(url, crlNumber, thisUpdate);
    }

    /// <summary>
    /// Gets CRL reference URL.
    /// </summary>
    public Uri URL { get; private set; }
    /// <summary>
    /// Gets referenced CRL number.
    /// </summary>
    public String CRLNumber { get; private set; }
    /// <summary>
    /// Gets referenced CRL <see cref="X509CRL2.ThisUpdate">ThisUpdate</see> field value.
    /// </summary>
    public DateTime ThisUpdate { get; private set; }

    void m_initialize(String url, String crlNumber, DateTime thisUpdate) {
        Oid = _oid;
        URL = new Uri(url);
        CRLNumber = crlNumber;
        ThisUpdate = thisUpdate;
    }
    void m_decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        if (asn.Tag == 48) {
            asn.MoveNext();
            do {
                StringBuilder sb;
                switch (asn.Tag) {
                    case 160:
                        sb = new StringBuilder();
                        foreach (Byte item in asn.GetPayload()) {
                            sb.Append(Convert.ToChar(item));
                        }
                        URL = new Uri(sb.ToString());
                        break;
                    case 161:
                        sb = new StringBuilder();
                        foreach (Byte item in asn.GetPayload()) {
                            sb.Append(Convert.ToChar(item) + " ");
                        }
                        CRLNumber = sb.ToString();
                        break;
                    case 162:
                        ThisUpdate = new Asn1GeneralizedTime(asn.GetPayload()).Value;
                        break;
                }
            } while (asn.MoveNext());
        }
    }
}