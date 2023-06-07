using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Exceptions;

namespace PKI.Web;
/// <summary>
/// The <strong>WebSSL</strong> class is used to verify remote server SSL certificate.
/// </summary>
public class WebSSL {

    /// <param name="request">an instance of <see cref="HttpWebRequest"/> that contains remote server connection properties.</param>
    /// <exception cref="ArgumentNullException">If <strong>request</strong> parameter is <strong>null</strong> or <strong>empty</strong>.</exception>
    /// <exception cref="ArgumentException">If connection URL scheme is not 'HTTPS'.</exception>
    public WebSSL(WebRequest request) {
        if (request == null) { throw new ArgumentNullException(nameof(request)); }
        if (request.RequestUri.Scheme.ToLower() != "https") {
            throw new ArgumentException("Only 'HTTPS' URL scheme is supported.");
        }
        m_initialize(request);
    }

    /// <summary>
    /// Gets original connection URL.
    /// </summary>
    public Uri OriginalUri { get; private set; }
    /// <summary>
    /// Gets returned connection URL.
    /// </summary>
    public Uri ReturnedUri { get; private set; }
    /// <summary>
    /// Gets server SSL certificate.
    /// </summary>
    public X509Certificate2 Certificate { get; private set; }
    /// <summary>
    /// Gets entire SSL certificate chain returned by web server.
    /// </summary>
    public X509Certificate2Collection Pkcs7Chain { get; private set; }
    /// <summary>
    /// Gets certificate subject name.
    /// </summary>
    public X500DistinguishedName Subject { get; private set; }
    /// <summary>
    /// Gets certificate issuer.
    /// </summary>
    public X500DistinguishedName Issuer { get; private set; }
    /// <summary>
    /// Identifies whether the name (or names) in the certificate matches the one specified in the request.
    /// </summary>
    public Boolean NameMatch { get; private set; }
    /// <summary>
    /// Gets an array of Subject Alternative Names (SAN) if they are configured.
    /// </summary>
    public String[] SubjectAlternativeNames { get; private set; }
    /// <summary>
    /// Gets the status of the certificate. <strong>True</strong> if the certificate is valid, otherwise <strong>False</strong>.
    /// </summary>
    public Boolean CertificateIsValid { get; private set; }
    /// <summary>
    /// Gets certificate chain error information.
    /// </summary>
    public X509ChainStatus[] ErrorInformation { get; private set; }
    /// <summary>
    /// Gets original HTTP response.
    /// </summary>
    public HttpWebResponse Response { get; private set; }
    /// <summary>
    /// Gets or sets the behavior for certificate chain building. If the property is set to <strong>True</strong>, user root certificates are allowed
    /// to establish a trust to a certificate. Otherwise, local system (machine) store is used.
    /// </summary>
    public Boolean UserContext { get; set; }
    internal HttpWebRequest Request { get; private set; }

    void m_initialize(WebRequest request) {
        OriginalUri = request.RequestUri;
        Request = (HttpWebRequest)request;
    }
    /// <summary>
    /// Submits HTTP request to a remote server and updates current object instance.
    /// </summary>
    public void SendRequest() {
        if (Request != null) {
            List<String> san = new List<String>();
            X509Chain Chain = new X509Chain(!UserContext);
            Pkcs7Chain = new X509Certificate2Collection();
            // add inline delegate definition
            ServicePointManager.ServerCertificateValidationCallback =
                delegate (Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) {
                // check if web server returns multiple certificates
                if (chain.ChainElements.Count > 1) {
                    foreach (X509ChainElement item in chain.ChainElements) {
                        Pkcs7Chain.Add(item.Certificate);
                        // add each certificate to X509Chain.ExtraStore, so certificate chaining engine
                        // will be able to use them for chain building
                        Chain.ChainPolicy.ExtraStore.Add(item.Certificate);
                    }
                }
                if (((Int32)sslPolicyErrors & (Int32)SslPolicyErrors.RemoteCertificateNameMismatch) == 0) {
                    NameMatch = true;
                }
                return true;
            };
            try {
                Response = (HttpWebResponse)Request.GetResponse();
                ReturnedUri = Response.ResponseUri;
                if (Request.ServicePoint.Certificate != null) {
                    Certificate = new X509Certificate2(Request.ServicePoint.Certificate);

                    Subject = Certificate.SubjectName;
                    Issuer = Certificate.IssuerName;
                    if (Certificate.Extensions.Count > 0) {
                        X509Extension rawExtension = Certificate.Extensions[X509ExtensionOid.SubjectAlternativeNames];
                        if (rawExtension != null) {
                            var sanExtension = new X509SubjectAlternativeNamesExtension(rawExtension, false);
                            san.AddRange(sanExtension.AlternativeNames.Select(x => x.Format(false)));
                        }
                    }
                    SubjectAlternativeNames = san.ToArray();
                    // add other settings for X509Chain and validate server certificate.
                    Chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                    CertificateIsValid = Chain.Build(Certificate);
                    ErrorInformation = Chain.ChainStatus;
                }
            } catch {
                if (!Request.HaveResponse) { throw; }
            } finally {
                Chain.Reset();
                if (Response != null && Response.ContentLength > 0) { Response.Close(); }
                ServicePointManager.ServerCertificateValidationCallback = null;
            }
        } else { throw new UninitializedObjectException(); }
    }
}
