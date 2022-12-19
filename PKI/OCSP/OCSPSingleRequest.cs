using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PKI.Exceptions;
using PKI.Utils;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace PKI.OCSP {
    /// <summary>
    /// This class represents a single OCSP request entry which include information about the certificate to verify
    /// and optional extensions.
    /// </summary>
    /// <remarks>Currently only <strong>Service Locator</strong> extension is supported.</remarks>
    public class OCSPSingleRequest {
        readonly List<X509Extension> _listExtensions = new();

        /// <summary>
        /// Intitializes a new instance of <strong>OCSPSingleRequest</strong> class from a certificate to include
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
            if (cert == null) { throw new ArgumentNullException(nameof(cert)); }
            if (cert.Handle.Equals(IntPtr.Zero)) { throw new UninitializedObjectException(); }
            m_initialize(null, cert, serviceLocator);
        }
        /// <summary>
        /// Intitializes a new instance of <strong>OCSPSingleRequest</strong> class from a certificate to include
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
            if (issuer == null) { throw new ArgumentNullException(nameof(issuer)); }
            if (leafCert == null) { throw new ArgumentNullException(nameof(leafCert)); }
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
        public X509ExtensionCollection Extensions {
            get {
                X509ExtensionCollection retValue = new X509ExtensionCollection();
                foreach (X509Extension item in _listExtensions) { retValue.Add(item); }
                return retValue;
            }
        }
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
            if (serviceLocator) { m_generateextensions(cert); }
        }
        void m_generateextensions(X509Certificate2 cert) {
            List<Byte> sext = new List<Byte>();
            Oid oid = new Oid(X509ExtensionOid.ServiceLocator);

            sext.AddRange(cert.IssuerName.RawData);
            if (cert.Extensions.Count > 0) {
                X509Extension ext = cert.Extensions[X509ExtensionOid.AuthorityInformationAccess];
                if (ext != null) {
                    sext.AddRange(ext.RawData);
                }
            }
            sext = new List<Byte>(Asn1Utils.Encode(sext.ToArray(), 48));
            _listExtensions.Add(new X509Extension(oid, sext.ToArray(), false).ConvertExtension());
        }
        /// <summary>
        /// Encodes OCSPSingleRequest object to a ASN.1-encoded byte aray.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        public Byte[] Encode() {
            if (String.IsNullOrEmpty(CertId.SerialNumber)) { throw new UninitializedObjectException(); }
            List<Byte> rawData = new List<Byte>();
            rawData.AddRange(CertId.Encode());
            if (Extensions.Count > 0) {
                Byte[] contentspecific0 = Extensions.Encode();
                rawData.AddRange(Asn1Utils.Encode(contentspecific0, 160));
            }
            return Asn1Utils.Encode(rawData.ToArray(), 48); // Request
        }
    }
}
