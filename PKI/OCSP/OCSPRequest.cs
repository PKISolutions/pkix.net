using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using PKI.Exceptions;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tools.MessageOperations;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace PKI.OCSP;

/// <summary>
/// Represents an OCSP Request object. This object is used to create and submit a request to an OCSP Responder.
/// </summary>
public class OCSPRequest {
    readonly List<X509Extension> _listExtensions = new();
    readonly X509Certificate2Collection _signerChain = new();
    Oid2[] responseAlgIDs = { new("sha1RSA", false) };
    Oid signatureAlgID = new("sha1RSA");
    Boolean includeFullSigChain;
    ICredentials creds;

    /// <summary>
    /// Initializes a new instance of the <see cref="OCSPRequest"/> class using the <see cref="X509Certificate2"/> object.
    /// </summary>
    /// <param name="cert">An <see cref="X509Certificate2"/> object to verify against OCSP Responder.</param>
    /// <remarks>This constructor will use OCSP URLs (if any) of the specified certificate.</remarks>
    public OCSPRequest(X509Certificate2 cert) {
        if (cert == null) { throw new ArgumentNullException(nameof(cert)); }
        if (cert.Handle.Equals(IntPtr.Zero)) { throw new UninitializedObjectException(); }
        initializeFromCert(cert);
    }
    /// <summary>
    /// Initializes a new instance of the <see cref="OCSPRequest"/> class using the <see cref="X509Certificate2Collection"/> object
    /// and <see cref="Uri"/> object.
    /// </summary>
    /// <param name="certs">Certificate collection to include in request.</param>
    public OCSPRequest(X509Certificate2Collection certs) {
        if (certs == null || certs.Count <= 0) { throw new ArgumentNullException(nameof(certs)); }
        if (!verifyCerts(certs)) {
            throw new Exception("One or more certificate in collection has distinct issuer");
        }
        initializeFromCerts(certs);
    }
    /// <summary>
    /// Initializes a new instance of <strong>OCSPRequest</strong> using issuer certificate, an array of
    /// certificates to verify and indication whether to include <strong>ServiceLocator</strong> extension
    /// to the request.
    /// </summary>
    /// <param name="certs">
    /// An <see cref="X509Certificate2Collection"/> object that contains an array of certificates to verify.
    /// </param>
    /// <param name="issuer">
    /// An <see cref="X509Certificate2"/> object that represents issuer certificate.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <strong>certs</strong> parameter is an empty sequence.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// Either, <strong>issuer</strong> and/or <strong>certs</strong> parameter is null.
    /// </exception>
    public OCSPRequest(X509Certificate2Collection certs, X509Certificate2 issuer) {
        if (issuer == null) { throw new ArgumentNullException(nameof(issuer)); }
        if (certs == null) { throw new ArgumentNullException(nameof(certs)); }
        if (issuer.Handle.Equals(IntPtr.Zero)) { throw new ArgumentException("The issuer certificate is invalid"); }
        if (certs.Count == 0) { throw new ArgumentException("Empty array in 'certs' parameter"); }
        initializeFromCertsAndIssuer(certs, issuer);
    }
    /// <summary>
    ///		Initializes a new instance of <strong>OCSPRequest</strong> from an array of single request items.
    /// </summary>
    /// <param name="requestList">
    ///		An array of request items to include in the OCSP request.
    /// </param>
    /// <exception cref="ArgumentException">
    ///		<strong>requestList</strong> parameter is null.
    /// </exception>
    ///	<exception cref="ArgumentNullException">
    ///		Collection in the <strong>requestList</strong> parameter is an empty sequence.
    /// </exception>
    public OCSPRequest(OCSPSingleRequestCollection requestList) {
        if (requestList == null) { throw new ArgumentNullException(nameof(requestList)); }
        if (requestList.Count == 0) { throw new ArgumentException("Request list is empty"); }
        RequestList = requestList;
    }

    /// <summary>
    /// Gets OCSP Request version. Currently only version 1 is defined.
    /// </summary>
    public Int32 Version => 1;

    /// <summary>
    /// Indicates whether the client chose to add <strong>Nonce</strong> extension.
    /// </summary>
    /// <remarks>If <strong>Nonce</strong> extension is included in the request, OCSP Responder MUST ignore all cached pre-generated
    /// response and build response by using the most actual revocation information. OCSP server SHOULD include
    /// nonce value in the response, but OCSP responders are not obligated to return nonce extension.
    /// For detailed information see <see href="http://tools.ietf.org/html/rfc2560.html">RFC2560</see>.
    /// </remarks>
    public Boolean Nonce { get; set; }
    /// <summary>
    /// As a Nonce extension value, a <see cref="DateTime.Ticks">Ticks</see> property value of <see cref="DateTime"/> class is used.
    /// </summary>
    public String NonceValue { get; private set; }
    /// <summary>
    /// Gets certificate identification object collection. This object is equavivalent to singleRequest
    /// structure in ASN.1 module.
    /// </summary>
    public OCSPSingleRequestCollection RequestList { get; private set; }
    /// <summary>
    /// Gets optional OCSP Request extensions. This may include <strong>Nonce</strong> and/or <strong>Service Locator</strong> extensions.
    /// </summary>
    public X509ExtensionCollection Extensions {
        get {
            if (_listExtensions.Count == 0) { return null; }
            X509ExtensionCollection retValue = new X509ExtensionCollection();
            foreach (X509Extension item in _listExtensions) { retValue.Add(item); }
            return retValue;
        }
    }
    /// <summary>
    /// Gets or sets the URL of the OCSP responder service. URL can be retrieved from certificate's AIA
    /// extension.
    /// </summary>
    public Uri URL { get; set; }
    /// <summary>
    /// Gets the certificate used to sign this request. If the request is not signed, this property is null.
    /// </summary>
    public X509Certificate2 SignerCertificate { get; private set; }
    /// <summary>
    /// Gets or sets web proxy information that will be used to connect OCSP server.
    /// </summary>
    public WebProxy Proxy { get; set; }
    /// <summary>
    /// Gets an array of supported signature algorithms that OCSP server shall use to sign response.
    /// Default algorithm is <strong>sha1RSA</strong>.
    /// </summary>
    /// <remarks>OCSP server may return an error </remarks>
    public Oid2[] AcceptedSignatureAlgorithms {
        get => responseAlgIDs;
        set {
            if (value.Any(oid => oid.OidGroup != OidGroupEnum.SignatureAlgorithm)) {
                throw new InvalidDataException("One or more object identifiers are invalid.");
            }
            responseAlgIDs = value;
        }
    }
    /// <summary>
    /// Gets the raw data of a OCSP request. This data is sent to OCSP responder.
    /// </summary>
    public Byte[] RawData { get; private set; }

    void initializeFromCert(X509Certificate2 cert) {
        RequestList = new OCSPSingleRequestCollection { new(cert, false) };
        URL = getOcspUrl(new[] { cert });
    }
    void initializeFromCerts(X509Certificate2Collection certs) {
        RequestList = new OCSPSingleRequestCollection();
        foreach (X509Certificate2 cert in certs) {
            RequestList.Add(new OCSPSingleRequest(cert, false));
        }
    }
    void initializeFromCertsAndIssuer(X509Certificate2Collection certs, X509Certificate2 issuer) {
        RequestList = new OCSPSingleRequestCollection();
        foreach (var cert in certs) {
            RequestList.Add(new OCSPSingleRequest(issuer, cert, false));
        }
    }
    List<Byte> buildTbsRequest(X500DistinguishedName requester) {
        List<Byte> tbsRequest = new List<Byte>();
        if (requester != null) {
            X509AlternativeName requesterName = new X509AlternativeName(X509AlternativeNamesEnum.DirectoryName, requester);
            tbsRequest.AddRange(Asn1Utils.Encode(requesterName.RawData, 0xa1));
        }
        tbsRequest.AddRange(RequestList.Encode());
        if (Nonce) {
            _listExtensions.Add(new X509NonceExtension());
            Byte[] extensionsBytes = Asn1Utils.Encode(Extensions.Encode(), 162);
            tbsRequest.AddRange(extensionsBytes);
            NonceValue = _listExtensions[_listExtensions.Count - 1].Format(false).Trim();
        }
        return Asn1Utils.Encode(tbsRequest.ToArray(), 48).ToList();
    }
    void signRequest(X509Certificate2 signerCert) {
        List<Byte> tbsRequest = buildTbsRequest(signerCert.SubjectName);
        Byte[] signature;

        using (var signerInfo = new MessageSigner(signerCert, new Oid2(signatureAlgID, false))) {
            signature = signerInfo.SignData(tbsRequest.ToArray());
        }
        SignerCertificate = signerCert;
        if (includeFullSigChain) {
            buildSignerCertChain();
        } else {
            _signerChain.Add(signerCert);
        }
        AlgorithmIdentifier algId = new AlgorithmIdentifier(signatureAlgID, new Byte[0]);
        List<Byte> signatureInfo = new List<Byte>(algId.RawData);
        signatureInfo.AddRange(new Asn1BitString(signature, false).RawData);
        signatureInfo.AddRange(Asn1Utils.Encode(_signerChain.Encode(), 0xa0));
        tbsRequest.AddRange(Asn1Utils.Encode(Asn1Utils.Encode(signatureInfo.ToArray(), 48), 0xa0));
        RawData = Asn1Utils.Encode(tbsRequest.ToArray(), 48);
    }
    void buildSignerCertChain() {
        X509Chain chain = new X509Chain {
                                            ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck }
                                        };
        chain.Build(SignerCertificate);
        for (Int32 index = 0; index < chain.ChainElements.Count; index++) {
            X509Certificate2 cert = chain.ChainElements[index].Certificate;
            if (index > 0 && cert.Subject == cert.Issuer) { break; }
            _signerChain.Add(cert);
        }
        chain.Reset();
    }
    String prepareGetUrl() {
        String target = URL.OriginalString.Replace("\0", null);

        if (!target.EndsWith("/")) {
            target += "/";
        }
        return target + HttpUtility.UrlEncode(Convert.ToBase64String(RawData));
    }
    void prepareWebClient(WebClient wc) {
        Version ver = Assembly.GetExecutingAssembly().GetName().Version;
        wc.Headers.Add("Content-Type", "application/ocsp-request");
        wc.Headers.Add("Accept", "*/*");
        wc.Headers.Add("User-Agent", $"PowerShell-PKI-Module/{ver.Major}.{ver.Minor}");
        wc.Headers.Add("Cache-Control", "no-cache");
        wc.Headers.Add("Pragma", "no-cache");
    }
    void prepareOcspRequest() {
        if (String.IsNullOrEmpty(URL?.AbsoluteUri)) {
            throw new InvalidOperationException("The OCSP server URL is not found. Please, specify the URL explicitly");
        }
        if (SignerCertificate == null) {
            Encode();
        } else {
            SignRequest(SignerCertificate, includeFullSigChain, signatureAlgID);
        }
    }
    OCSPResponse sendGetRequest() {
        using var wc = new WebClient { Proxy = Proxy, Credentials = creds };
        prepareWebClient(wc);
        String target = prepareGetUrl();
        Byte[] responseBytes = wc.DownloadData(target);
        return new OCSPResponse(responseBytes, this, wc);
    }
    OCSPResponse sendPostRequest() {
        using var wc = new WebClient { Proxy = Proxy, Credentials = creds };
        prepareWebClient(wc);
        String target = URL.OriginalString.Replace("\0", null);
        Byte[] responseBytes = wc.UploadData(target, "POST", RawData);
        return new OCSPResponse(responseBytes, this, wc);
    }
    static Uri getOcspUrl(IEnumerable<X509Certificate2> certs) {
        foreach (X509Certificate2 cert in certs.Where(x => !x.Handle.Equals(IntPtr.Zero))) {
            X509Extension aiaExtension = cert.Extensions[X509ExtensionOid.AuthorityInformationAccess];
            if (aiaExtension == null) {
                continue;
            }
            X509AuthorityInformationAccessExtension aia = new X509AuthorityInformationAccessExtension(aiaExtension.RawData, false);
            if (aia.OnlineCertificateStatusProtocol == null || aia.OnlineCertificateStatusProtocol.Length == 0) {
                continue;
            }
            return new Uri(aia.OnlineCertificateStatusProtocol[0].Trim());
        }
        return null;
    }
    static Boolean verifyCerts(X509Certificate2Collection certs) {
        if (certs.Count <= 0) {
            return false;
        }

        HashSet<String> issuers = new HashSet<String>();
        foreach (X509Certificate2 cert in certs) {
            if (cert.Handle.Equals(IntPtr.Zero)) {
                return false;
            }
            issuers.Add(cert.Issuer.ToLower());
        }
        return issuers.Count == 1;
    }

    ///  <summary>
    /// 	Digitally signs the OCSP request. The method uses "<strong>sha1RSA</strong>" signature
    ///		algorithm by default.
    ///  </summary>
    ///  <param name="signerCert">
    /// 	An <see cref="X509Certificate2"/> object that represents signer certificate.
    ///  </param>
    ///  <param name="includeFullChain">
    ///		Specifies whether the full certificate chain is included in the digital signature. If the
    ///		parameter is <strong>False</strong>, only signer certificate is included in the signature.
    ///  </param>
    /// <exception cref="ArgumentException">
    ///  Signer certificate is null.
    ///  </exception>
    ///  <exception cref="ArgumentNullException">
    ///  Signer certificate do not contain private key.
    ///  </exception>
    ///  <remarks>
    ///  OCSP server may return an error if it do not support signed requests.
    ///  <para>Once the request is signed, no modifications to the request object are allowed.</para>
    ///  </remarks>
    public void SignRequest(X509Certificate2 signerCert, Boolean includeFullChain) {
        SignRequest(signerCert, includeFullChain, signatureAlgID);
    }
    ///  <summary>
    /// 	Digitally signs the OCSP request.
    ///  </summary>
    ///  <param name="signerCert">
    /// 	An <see cref="X509Certificate2"/> object that represents signer certificate.
    ///  </param>
    ///  <param name="includeFullChain">
    ///		Specifies whether the full certificate chain is included in the digital signature. If the
    ///		parameter is <strong>False</strong>, only signer certificate is included in the signature.
    ///  </param>
    /// <param name="signatureAlgorithm">
    ///		Specifies the signature algorithm used to sign the OCSP request.
    /// </param>
    /// <exception cref="ArgumentException">
    ///  Signer certificate is null.
    ///  </exception>
    ///  <exception cref="ArgumentNullException">
    ///  Signer certificate do not contain private key.
    ///  </exception>
    ///  <remarks>
    ///  OCSP server may return an error if it do not support signed requests.
    ///  <para>Once the request is signed, no modifications to the request object are allowed.</para>
    ///  </remarks>
    public void SignRequest(X509Certificate2 signerCert, Boolean includeFullChain, Oid signatureAlgorithm) {
        if (signerCert == null) { throw new ArgumentNullException(nameof(signerCert)); }
        if (!signerCert.HasPrivateKey) {
            throw new ArgumentException("The certificate do not contain private key.");
        }
        includeFullSigChain = includeFullChain;
        signatureAlgID = signatureAlgorithm;
        signRequest(signerCert);
    }
    /// <summary>
    /// Encodes OCSP request based on a current information and populates <see cref="RawData"/> property.
    /// After encoding, the object cannot be modified 
    /// </summary>
    public void Encode() {
        RawData = Asn1Utils.Encode(buildTbsRequest(null).ToArray(), 48);
    }
    /// <summary>
    /// Sends OCSP request (encoded raw data) to a OCSP responder specified in <see cref="URL"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The OCSP server URL is NULL.</exception>
    /// <returns>
    /// <see cref="OCSPResponse"/> object that represents OCSP response.
    /// </returns>
    /// <remarks>
    /// The following behavior is used by this method:
    /// <para>
    /// A <strong>GET</strong> network method is attempted. If GET fails with either, HTTP404 (Not Found)
    /// or HTTP405 (Method Not Allowed), a <strong>POST</strong> network method is used. If GET method fails
    /// with any other HTTP error code, POST method is not used.
    /// </para>
    /// </remarks>
    public OCSPResponse SendRequest() {
        prepareOcspRequest();
        try {
            return sendGetRequest();
        } catch (WebException e) {
            var statusCode = ((HttpWebResponse)e.Response).StatusCode;
            if (statusCode == HttpStatusCode.MethodNotAllowed || statusCode == HttpStatusCode.NotFound) {
                return sendPostRequest();
            }

            throw;
        }
    }
    /// <summary>
    /// Sends OCSP request (encoded raw data) to a OCSP responder specified in <see cref="URL"/> property
    /// by using specific network method.
    /// </summary>
    /// <param name="networkMethod">
    /// Specifies the network method to attempt. Can be either, <strong>GET</strong> or <strong>POST</strong>.
    /// </param>
    /// <exception cref="InvalidOperationException">The OCSP server URL is NULL.</exception>
    /// <exception cref="ArgumentException">The network method is invalid.</exception>
    /// <returns>
    ///     <see cref="OCSPResponse"/> object that represents OCSP response.
    /// </returns>
    public OCSPResponse SendRequest(String networkMethod) {
        prepareOcspRequest();
        switch (networkMethod.ToUpper()) {
            case "GET":
                return sendGetRequest();
            case "POST":
                return sendPostRequest();
            default:
                throw new ArgumentException("The network method is invalid. Must be either, NULL, GET or POST.");

        }
    }
    /// <summary>
    /// Gets or sets the proxy used by OCSP request.
    /// </summary>
    /// <param name="proxy">Proxy settings.</param>
    [Obsolete("This method is moved to a property.", true)]
    public void SetProxy(WebProxy proxy) {
        Proxy = proxy;
    }
    /// <summary>
    /// Gets or sets the network credentials that are sent to a OCSP server and used to authenticate the request.
    /// </summary>
    /// <param name="credentials">Credentials to use.</param>
    /// <remarks>
    ///		OCSP servers should not use authentication for incoming requests.
    /// </remarks>
    public void SetCredential(ICredentials credentials) {
        creds = credentials;
    }
}