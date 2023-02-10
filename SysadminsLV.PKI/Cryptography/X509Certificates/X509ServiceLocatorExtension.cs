using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Defines the <strong>id-pkix-ocsp-service-locator</strong> extension (defined in <see href="http://tools.ietf.org/html/rfc2560">RFC2560</see>).
/// This class cannot be inherited.
/// </summary>
public sealed class X509ServiceLocatorExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.ServiceLocator, "OCSP Service Locator");
    readonly List<String> _urlList = new();
    Byte[] AIARaw;

    /// <summary>
    /// Initializes a new instance of the <strong>X509ServiceLocatorExtension</strong> class.
    /// </summary>
    /// <param name="cert">An <see cref="X509Certificate2"/> object from which to construct the extension.</param>
    public X509ServiceLocatorExtension(X509Certificate2 cert) {
        if (cert == null) {
            throw new ArgumentNullException(nameof(cert));
        }
        m_initialize(cert);
    }

    /// <param name="value">The encoded data to use to create the extension.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    public X509ServiceLocatorExtension(AsnEncodedData value, Boolean critical) : base(_oid, value.RawData, critical) {
        m_decode(value.RawData);
    }

    /// <summary>
    /// Gets issuer X.500 distinguished name.
    /// </summary>
    public String IssuerName { get; private set; }

    /// <summary>
    /// Gets an array of URLs contained in <strong>Authority Information Access</strong> extension.
    /// </summary>
    public String[] AuthorityInformationAccess => _urlList.ToArray();

    void m_initialize(X509Certificate2 cert) {
        var rawData = new List<Byte>();
        rawData.AddRange(cert.IssuerName.RawData);
        if (cert.Extensions.Count > 0) {
            X509Extension ext = cert.Extensions[X509ExtensionOid.AuthorityInformationAccess];
            if (ext != null) {
                AIARaw = ext.RawData;
                rawData.AddRange(ext.RawData);
                extractUrls(cert);
            }
        }
        rawData = new List<Byte>(Asn1Utils.Encode(rawData.ToArray(), 48));
        IssuerName = cert.Issuer;
        Critical = false;
        Oid = _oid;
        RawData = rawData.ToArray();
    }
    void extractUrls(X509Certificate2 cert) {
        X509Extension extension = cert.Extensions[X509ExtensionOid.AuthorityInformationAccess];
        if (extension != null) {
            var aiaExtension = (X509AuthorityInformationAccessExtension)extension.ConvertExtension();
            _urlList.AddRange(aiaExtension.CertificationAuthorityIssuer);
            _urlList.AddRange(aiaExtension.OnlineCertificateStatusProtocol);
        }
    }
    void m_decode(Byte[] rawData) {
        //TODO
    }

    /// <summary>
    /// Returns a formatted version of the Abstract Syntax Notation One (ASN.1)-encoded data as a string.
    /// </summary>
    /// <param name="multiLine"><strong>True</strong> if the return string should contain carriage returns; otherwise, <strong>False</strong>.</param>
    /// <returns>A formatted string that represents the Abstract Syntax Notation One (ASN.1)-encoded data.</returns>
    public override String Format(Boolean multiLine) {
        var SB = new StringBuilder();
        SB.Append("[0]Certificate issuer: ");
        if (multiLine) {
            SB.Append(Environment.NewLine + "     ");
        }
        SB.Append(IssuerName);
        if (multiLine) {
            SB.AppendLine();
        }
        if (AIARaw.Length > 1) {
            if (!multiLine) { SB.Append(", "); }
            var aia = new X509Extension(new Oid(X509ExtensionOid.AuthorityInformationAccess), AIARaw, false);
            SB.Append(aia.Format(multiLine));
        }
        return SB.ToString();
    }
}