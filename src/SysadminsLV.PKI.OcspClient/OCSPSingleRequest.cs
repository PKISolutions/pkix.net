using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.OcspClient;

/// <summary>
/// This class represents a single OCSP request entry which include information about the certificate to verify
/// and optional extensions.
/// </summary>
/// <remarks>Currently, only <strong>Service Locator</strong> extension is supported.</remarks>
public class OCSPSingleRequest {
    readonly X509ExtensionCollection _extensions = new();

    /// <summary>
    /// Initializes a new instance of <strong>OCSPSingleRequest</strong> class from a certificate to include
    /// in the request and value that indicates whether to include <see cref="X509ServiceLocatorExtension"/>
    /// extension.
    /// </summary>
    /// <param name="cert">An <see cref="X509Certificate2"/> object that represents a certificate to verify.</param>
    /// <param name="serviceLocator">Specifies whether to include <strong>Service Locator</strong> extension in request.</param>
    /// <remarks>
    /// <strong>Service Locator</strong> extension is used only when target OCSP responder is configured as
    /// a OCSP-Proxy and is capable to forward original request to a authoritative responder. Normally this
    /// extension SHOULD NOT be used.
    /// </remarks>
    /// <exception cref="ArgumentNullException">The <strong>cert</strong> parameter is null.</exception>
    public OCSPSingleRequest(X509Certificate2 cert, Boolean serviceLocator) {
        if (cert == null) {
            throw new ArgumentNullException(nameof(cert));
        }

        m_initialize(null, cert, serviceLocator);
    }
    /// <summary>
    /// Initializes a new instance of <strong>OCSPSingleRequest</strong> class from a certificate to include
    /// in the request, certificate issuer and a value that indicates whether to include
    /// <see cref="X509ServiceLocatorExtension"/> extension.
    /// </summary>
    /// <param name="issuer">
    ///	An <see cref="X509Certificate2"/> object that represents a certificate which is an issuer of the
    /// certificate in the <strong>leafCert</strong> parameter.
    /// </param>
    /// <param name="leafCert">
    /// An <see cref="X509Certificate2"/> object that represents a certificate to include in the request.
    /// </param>
    /// <param name="serviceLocator">
    ///	Indicates whether to include <see cref="X509ServiceLocatorExtension"/> extension.
    /// </param>
    /// <remarks>
    /// <strong>Service Locator</strong> extension is used only when target OCSP responder is configured as
    /// a OCSP-Proxy and is capable to forward original request to a authoritative responder. Normally this
    /// extension SHOULD NOT be used.
    /// </remarks>
    public OCSPSingleRequest(X509Certificate2 issuer, X509Certificate2 leafCert, Boolean serviceLocator) {
        if (issuer == null) {
            throw new ArgumentNullException(nameof(issuer));
        }
        if (leafCert == null) {
            throw new ArgumentNullException(nameof(leafCert));
        }

        m_initialize(issuer, leafCert, serviceLocator);
    }

    /// <summary>
    /// Gets an information about the certificate to verify.
    /// </summary>
    public CertID CertId { get; private set; }
    /// <summary>
    /// Gets optional extensions associated with the certificate in the subject.
    /// </summary>
    /// <remarks>
    /// Currently only <strong>Service Locator</strong> extension is supported.
    /// </remarks>
    public X509ExtensionCollection Extensions => _extensions.Duplicate();
    /// <summary>
    /// Gets the name of the certificate in the question.
    /// </summary>
    public X500DistinguishedName CertificateName { get; private set; }

    void m_initialize(X509Certificate2 issuer, X509Certificate2 cert, Boolean serviceLocator) {
        CertId = issuer == null
            ? new CertID(cert)
            : new CertID(issuer, cert);
        CertificateName = cert.SubjectName;
        //List<Byte> rawData = new List<Byte>(CertId.Encode());
        if (serviceLocator) {
            buildRequestExtensions(cert);
        }
    }
    void buildRequestExtensions(X509Certificate2 cert) {
        var extnBytes = new List<Byte>();
        var oid = new Oid(X509ExtensionOid.ServiceLocator);

        extnBytes.AddRange(cert.IssuerName.RawData);
        if (cert.Extensions.Count > 0) {
            X509Extension ext = cert.Extensions[X509ExtensionOid.AuthorityInformationAccess];
            if (ext != null) {
                extnBytes.AddRange(ext.RawData);
            }
        }
        extnBytes = new List<Byte>(Asn1Utils.Encode(extnBytes.ToArray(), 48));
        _extensions.Add(new X509Extension(oid, extnBytes.ToArray(), false).ConvertExtension());
    }
    /// <summary>
    /// Encodes OCSPSingleRequest object to a ASN.1-encoded byte aray.
    /// </summary>
    /// <returns>ASN.1-encoded byte array.</returns>
    public Byte[] Encode() {
        var rawData = new List<Byte>();
        rawData.AddRange(CertId.Encode());
        if (Extensions.Count > 0) {
            Byte[] contentspecific0 = Extensions.Encode();
            rawData.AddRange(Asn1Utils.Encode(contentspecific0, 160));
        }
        return Asn1Utils.Encode(rawData.ToArray(), 48); // Request
    }
}