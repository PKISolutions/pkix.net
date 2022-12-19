using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.Utils;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tools.MessageOperations;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace PKI.OCSP;

#region Oids
//id-kp-OCSPSigning				OBJECT IDENTIFIER ::= { id-kp 9 }
//id-pkix-ocsp					OBJECT IDENTIFIER ::= { id-ad-ocsp }
//id-pkix-ocsp-basic			OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.1 }
//id-pkix-ocsp-nonce			OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.2 }
//id-pkix-ocsp-crl				OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.3 }
//id-pkix-ocsp-response			OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.4 }
//id-pkix-ocsp-nocheck			OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.5 }
//id-pkix-ocsp-archive-cutoff	OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.6 }
//id-pkix-ocsp-service-locator	OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.7 }
#endregion
/// <summary>
/// Represents an OCSP response received from OCSP responder against previously submitted OCSP Request.
/// </summary>
public class OCSPResponse {
    readonly WebClient _wc;
    readonly List<X509Extension> _listExtensions = new();
    Asn1Reader asn;

    internal OCSPResponse(Byte[] rawData, OCSPRequest req, WebClient web) {
        RawData = rawData;
        Request = req;
        _wc = web;
        decodeResponse();
    }
    internal OCSPResponse(Byte[] rawData) {
        RawData = rawData;
        decodeResponse();
    }

    /// <summary>
    /// Gets OCSP response version. Currently only version 1 is defined.
    /// </summary>
    public Int32 Version { get; private set; }
    /// <summary>
    /// Gets response type (for example, <strong>id_pkix_ocsp_basic</strong>, which means Basic OCSP Response type).
    /// </summary>
    public OCSPResponseType ResponseType { get; private set; }
    /// <summary>
    /// Gets response status. Response status indicates whether the OCSP responder was able to process the request
    /// and obtain information about requested certificate.
    /// </summary>
    /// <remarks><strong>Note:</strong> this property do not say anything about certificate status.</remarks>
    public OCSPResponseStatus ResponseStatus { get; private set; }
    /// <summary>
    /// Gets the the time at which the OCSP responder signed this response.
    /// </summary>
    public DateTime ProducedAt { get; private set; }
    /// <summary>
    /// Indicates whether the <strong>Nonce</strong> extension is included in the response.
    /// </summary>
    public Boolean NonceReceived { get; private set; }
    /// <summary>
    /// Gets Nonce extension value. This value (if extension is presented) MUST be exactly as specified in the request.
    /// </summary>
    public String NonceValue { get; private set; }
    /// <summary>
    /// Gets OCSP responder key ID (a hash calculated over responder's public key). If this property is empty,
    /// a <see cref="ResponderNameId"/> is used.
    /// </summary>
    public String ResponderKeyId { get; private set; }
    /// <summary>
    /// Gets OCSP responder name ID. If this property is empty, a <see cref="ResponderKeyId"/> is used.
    /// </summary>
    public X500DistinguishedName ResponderNameId { get; private set; }
    /// <summary>
    /// Gets original OCSP request object.
    /// </summary>
    public OCSPRequest Request { get; }
    /// <summary>
    /// Gets OCSP Signing certificate that was used to sign the response.
    /// </summary>
    public X509Certificate2Collection SignerCertificates { get; private set; }
    /// <summary>
    /// Gets a collection of OCSPSingleResponse objects, which contains revocation status about each requested certificate.
    /// </summary>
    public OCSPSingleResponseCollection Responses { get; private set; }
    /// <summary>
    /// Gets optional OCSP response extensions. This may contain Nonce extension.
    /// </summary>
    public X509ExtensionCollection ResponseExtensions {
        get {
            if (_listExtensions.Count == 0) { return null; }
            var retValue = new X509ExtensionCollection();
            foreach (X509Extension item in _listExtensions) { retValue.Add(item); }
            return retValue;
        }
    }
    /// <summary>
    /// Gets response HTTP headers.
    /// </summary>
    public WebHeaderCollection HttpHeaders => _wc?.ResponseHeaders;

    /// <summary>
    /// Indicates whether the signig certificate is valid for requested usage.
    /// </summary>
    /// <remarks>This check returns <strong>True</strong> under the following circumstances:
    /// <list type="bullet">
    /// <item>Is issued by the trusted certification authority.</item>
    /// <item>If it is delegated signing certificate, the certificate MUST contains id-kp-OCSPSigning
    /// Enhanced Key Usage .</item>
    /// <item>If it is delegated signing certificate, the certificate MUST contains OCSP id-pkix-ocsp-nocheck
    /// extension.</item>
    /// </list>
    /// If any of this check fails, the property returns <strong>False</strong>.
    /// </remarks>
    public Boolean SignerCertificateIsValid { get; private set; }
    /// <summary>
    /// Indicates whether the signature is valid.
    /// </summary>
    public Boolean SignatureIsValid { get; private set; }
    /// <summary>
    /// Gets error information returned by the certificate chaining engine.
    /// </summary>
    public X509ChainStatus[] ChainErrorInformation { get; private set; }
    /// <summary>
    /// Gets error and warning information about received response conformance with
    /// <see href="http://tools.ietf.org/html/rfc2560.html">RFC2560</see>.
    /// </summary>
    /// <remarks>Not all entries should be treated as an error. For example, if original request contains Nonce extension,
    /// OCSP Responder may not return this extension in the response.</remarks>
    public OCSPResponseComplianceError ResponseErrorInformation { get; private set; }
    /// <summary>
    /// Gets the algorithm used to create the signature of a response.
    /// </summary>
    /// <remarks>The object identifier <see cref="Oid">(Oid)</see> identifies the type of signature
    /// algorithm used by the responder.</remarks>
    public Oid SignatureAlgorithm { get; private set; }
    /// <summary>
    /// Gets encoded response's raw data.
    /// </summary>
    public Byte[] RawData { get; }

    void decodeResponse() {
        asn = new Asn1Reader(RawData);
        if (asn.Tag != 48) {
            throw new Asn1InvalidTagException("Response data is not valid ASN.1 encoded data.");
        }
        //response status
        asn.MoveNextAndExpectTags((Byte)Asn1Type.ENUMERATED);
        ResponseStatus = (OCSPResponseStatus)asn.GetPayload()[0];
        if (asn.NextOffset == 0) { return; }
        //responseBytesCS
        asn.MoveNextAndExpectTags(0xa0);
        asn.MoveNext();
        asn.MoveNext();
        decodeResponseType(new Asn1ObjectIdentifier(asn.GetTagRawData()).Value);
        asn.MoveNextAndExpectTags((Byte)Asn1Type.OCTET_STRING);
        //BasicOCSPResponse
        asn.MoveNextAndExpectTags(0x30);
        asn.MoveNext();
        //tbsResponseData
        var tbsResponseData = new Asn1Reader(asn.GetTagRawData());
        //decodetbsResponse(tbsResponseData);
        //signatureAlgorithm
        asn.MoveNextSibling();
        SignatureAlgorithm = new AlgorithmIdentifier(Asn1Utils.Encode(asn.GetPayload(), 48)).AlgorithmId;
        //signature
        asn.MoveNextSibling();
        Byte[] signature = asn.GetPayload().Skip(1).ToArray();
        // GenericArray.GetSubArray(asn1.Payload, 1, asn1.Payload.Length - 1);
        SignerCertificates = new X509Certificate2Collection();
        if (asn.MoveNext()) {
            asn.MoveNext();
            var cert = new Asn1Reader(asn.GetPayload());
            do {
                SignerCertificates.Add(new X509Certificate2(Asn1Utils.Encode(cert.GetPayload(), 48)));
            } while (cert.MoveNextSibling());
            verifySigner(SignerCertificates, true);
        } // optional. Find cert in store.
        verifyAll(tbsResponseData, signature, SignatureAlgorithm);
    }
    void decodeResponseType(Oid oid) {
        switch (oid.Value) {
            case "1.3.6.1.5.5.7.48.1.1":
                ResponseType = OCSPResponseType.id_pkix_ocsp_basic;
                break;
            case "1.3.6.1.5.5.7.48.1.4":
                ResponseType = OCSPResponseType.id_pkix_ocsp_response;
                break;
        }
    }
    void decodeTbsResponse(Asn1Reader tbsResponseData) {
        tbsResponseData.MoveNext();
        if (tbsResponseData.Tag == 160) {
            //Asn1Reader aversion = new Asn1Reader(tbsResponseData.RawData, tbsResponseData.PayloadStartOffset);
            var aversion = new Asn1Reader(tbsResponseData);
            aversion.MoveNext();
            Version = aversion.GetPayload()[0] + 1;
            tbsResponseData.MoveNextSibling();
        } else {
            Version = 1;
        }
        //responderID
        switch (tbsResponseData.Tag) {
            case 161:
                ResponderNameId = new X500DistinguishedName(tbsResponseData.GetPayload());
                tbsResponseData.MoveNextSibling();
                break;
            case 162:
                tbsResponseData.MoveNext();
                var SB = new StringBuilder();
                foreach (Byte element in tbsResponseData.GetPayload()) { SB.Append(element.ToString("X2")); }
                ResponderKeyId = SB.ToString();
                tbsResponseData.MoveNext();
                break;
            default:
                throw new Exception("Invalid tag at responderID. Expected 161 (byName) or 162 (byKey).");
        }
        //tbsResponseData.MoveNextCurrentLevel();
        ProducedAt = Asn1Utils.DecodeGeneralizedTime(tbsResponseData.GetTagRawData());
        if (DateTime.Now < ProducedAt.AddMinutes(-10)) {
            ResponseErrorInformation |= OCSPResponseComplianceError.ResponseNotTimeValid;
        }
        //responses
        tbsResponseData.MoveNext();
        //single response
        var responses = new Asn1Reader(tbsResponseData.GetTagRawData());
        responses.MoveNext();
        Int32 Offset;
        Responses = new OCSPSingleResponseCollection();
        do {
            var response = new Asn1Reader(responses);
            Offset = response.NextSiblingOffset;
            Responses.Add(new OCSPSingleResponse(response));
            if (Request != null) {
                foreach (OCSPSingleResponse item in Responses) {
                    Boolean certIdMatch = Request.RequestList.Any(x => x.CertId.Equals(item.CertId));
                    if (!certIdMatch) {
                        ResponseErrorInformation |= OCSPResponseComplianceError.CertIdMismatch;
                    }
                }
            }
        } while (Offset != 0);
        if (tbsResponseData.NextSiblingOffset != 0) {
            tbsResponseData.MoveNextSibling();
            if (tbsResponseData.Tag == 161) {
                var extensions = new X509ExtensionCollection();
                extensions.Decode(tbsResponseData.GetPayload());
                foreach (X509Extension item in extensions) {
                    _listExtensions.Add(item.ConvertExtension());
                    if (_listExtensions[_listExtensions.Count - 1].Oid.Value == X509ExtensionOid.OcspNonce) {
                        NonceReceived = true;
                        NonceValue = _listExtensions[_listExtensions.Count - 1].Format(false);
                    }
                }
            } else { throw new Exception("Unexpected tag at responseExtensions. Expected 161."); }
        }
    }
    void findCertInStore() {
        String[] storeNames = { "Root", "CA" };
        foreach (X509Store store in storeNames.Select(x => new X509Store(x, StoreLocation.CurrentUser))) {
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection findCerts = store.Certificates;
            X509Certificate2Collection findCert;
            if (ResponderNameId != null) {
                findCert = findCerts.Find(X509FindType.FindBySubjectDistinguishedName, ResponderNameId.Name, true);
                if (findCert.Count > 0) {
                    SignerCertificates.Add(findCert[0]);
                    verifySigner(findCert, false);
                }
            } else {
                findCert = findCerts.Find(X509FindType.FindBySubjectKeyIdentifier, ResponderKeyId, true);
                if (findCert.Count > 0) {
                    SignerCertificates.Add(findCert[0]);
                    verifySigner(findCert, false);
                }
            }
            store.Close();
        }
    }
    void verifyAll(Asn1Reader tbsResponseData, Byte[] signature, Oid signatureAlgorithm) {
        verifyHeaders();
        decodeTbsResponse(tbsResponseData);
        if (NonceReceived) {
            if (Request.NonceValue != NonceValue) {
                ResponseErrorInformation |= OCSPResponseComplianceError.NonceMismatch;
            }
        }
        if (SignerCertificates.Count > 0) {
            using var signerInfo = new MessageSigner(SignerCertificates[0], new Oid2(signatureAlgorithm, false));
            SignatureIsValid = signerInfo.VerifyData(tbsResponseData.GetRawData(), signature);
        } else {
            findCertInStore();
            if (SignerCertificates.Count > 0) {
                using var signerInfo =
                    new MessageSigner(SignerCertificates[0], new Oid2(signatureAlgorithm, false));
                SignatureIsValid = signerInfo.VerifyData(tbsResponseData.GetRawData(), signature);
            } else {
                ResponseErrorInformation |= OCSPResponseComplianceError.MissingCert;
            }
        }
        verifyResponses();
    }
    void verifyHeaders() {
        if (_wc == null) { return; }
        if (_wc.ResponseHeaders.Get("Content-type") != "application/ocsp-response") {
            ResponseErrorInformation |= OCSPResponseComplianceError.InvalidHTTPHeader;
        }
    }
    void verifyResponses() {
        if (Responses
            .Any(item => item.ThisUpdate > DateTime.Now || (item.NextUpdate != null && item.NextUpdate < DateTime.Now))) {
            ResponseErrorInformation |= OCSPResponseComplianceError.UpdateNotTimeValid;
        }
    }
    void verifySigner(X509Certificate2Collection certs, Boolean explicitCert) {
        X509Certificate2 cert = certs[0];
        SignerCertificateIsValid = true;
        var chain = new X509Chain {
                                      ChainPolicy = {
                                                        RevocationMode = X509RevocationMode.NoCheck
                                                    }
                                  };
        chain.ChainPolicy.ExtraStore.AddRange(certs);
        SignerCertificateIsValid = chain.Build(cert);
        if (!SignerCertificateIsValid) {
            ChainErrorInformation = chain.ChainStatus;
            SignerCertificateIsValid = false;
        }
        if (explicitCert) {
            X509Extension ocspRevNoCheck = cert.Extensions[X509ExtensionOid.OcspRevNoCheck];
            if (ocspRevNoCheck == null) {
                ResponseErrorInformation |= OCSPResponseComplianceError.MissingOCSPRevNoCheck;
                SignerCertificateIsValid = false;
            }
            X509Extension eku = cert.Extensions[X509ExtensionOid.EnhancedKeyUsage];
            if (eku == null) {
                ResponseErrorInformation |= OCSPResponseComplianceError.MissingOCSPSigningEKU;
                SignerCertificateIsValid = false;
            }
        }
    }

    /// <summary>
    /// Displays OCSP response signing certificates in a familiar UI. If multiple certificates are available,
    /// they are displayed as a certificate pick up list.
    /// </summary>
    public void DisplaySigningCertificateUI() {
        if (SignerCertificates.Count == 0) {
            throw new NullReferenceException("No signing certificates are available");
        }
        if (SignerCertificates.Count == 1) {
            X509Certificate2UI.DisplayCertificate(SignerCertificates[0]);
        } else if (SignerCertificates.Count > 1) {
            X509Certificate2UI.SelectFromCollection(SignerCertificates, "Response signing certificates", "", X509SelectionFlag.SingleSelection);
        }
    }
}