using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography.X509CertificateRequests;

/// <summary>
/// This class represents single PKCS#10 certificate request.
/// </summary>
public class X509CertificateRequest : X509CertificateRequestPkcs10 {
    /// <summary>
    /// Initializes a new instance of the <strong>X509CertificateRequest</strong> class defined from a sequence of bytes
    /// representing certificate request.
    /// </summary>
    /// <param name="rawData">A byte array containing data from a certificate request.</param>
    public X509CertificateRequest(Byte[] rawData) {
        RawData = rawData;
        m_initialize();
    }
    /// <summary>
    /// Initializes a new instance of the <strong>X509CertificateRequest</strong> class defined from a file.
    /// </summary>
    /// <param name="path">The path to a certificate request file.</param>
    public X509CertificateRequest(String path) {
        getBinaryData(path);
        m_initialize();
    }

    /// <summary>
    /// Gets request format. Can be either <strong>PKCS10</strong> or <strong>PKCS7</strong>.
    /// </summary>
    public X509CertificateRequestType RequestType { get; private set; }
    /// <summary>
    /// Gets external PKCS7/CMC envelope. External envelope is applicable only for PKCS7/CMC requests.
    /// </summary>
    public X509CertificateRequestCmc ExternalData { get; private set; }

    void getBinaryData(String path) {
        RawData = CryptBinaryConverter.CryptFileToBinary(path);
    }
    void m_initialize() {
        // at this point RawData is not null
        try {
            Decode(RawData);
            RequestType = X509CertificateRequestType.PKCS10;
        } catch {
            var cmc = new X509CertificateRequestCmc(RawData);
            Version = cmc.Content.Version;
            SubjectName = cmc.Content.SubjectName;
            PublicKey = cmc.Content.PublicKey;
            InternalExtensions.AddRange(cmc.Content.Extensions.Cast<X509Extension>());
            InternalAttributes.AddRange(cmc.Content.Attributes);
            SignatureAlgorithm = cmc.Content.SignatureAlgorithm;
            SignatureIsValid = cmc.Content.SignatureIsValid;
            ExternalData = cmc;
            RequestType = X509CertificateRequestType.PKCS7;
        }
    }
    // functions for ToString() method.
    void genPkcs10String(StringBuilder sb) {
        sb.Append(base.ToString());
    }
    void genPkcs7String(StringBuilder sb) {
        genPkcs10String(sb);
    }

    static X509CertificateRequestType getRequestFormat(Byte[] rawData) {
        // TODO: this is just silly, need to read the envelope using ASN and determine exact type.
        try {
            new X509CertificateRequestPkcs10(rawData);
            return X509CertificateRequestType.PKCS10;
        } catch {
            try {
                new X509CertificateRequestCmc(rawData);
                return X509CertificateRequestType.PKCS7;
            } catch {
                return X509CertificateRequestType.Invalid;
            }
        }
    }

    /// <summary>
    /// Gets the textual representation of the certificate request.
    /// </summary>
    /// <returns>Formatted textual representation of the certificate request.</returns>
    /// <remarks>
    /// If the certificate request type is <strong>PKCS#7</strong>, this method returns textual
    /// representation only for embedded <strong>PKCS#10</strong> certificate request. For full
    /// PKCS#7 dump use the <see cref="Object.ToString()">ToString</see> method of the
    /// <see cref="Pkcs.SignedPkcs7{T}"/> class.
    /// </remarks>
    public override String ToString() {
        var SB = new StringBuilder();
        switch (RequestType) {
            case X509CertificateRequestType.PKCS10:
                genPkcs10String(SB);
                break;
            case X509CertificateRequestType.PKCS7:
                genPkcs7String(SB);
                break;
            default:
                return base.ToString();
        }
        return SB.ToString();
    }

    /// <summary>
    /// Gets the certificate request format in the specified file. This method allows to determine whether the
    /// certificate request is encoded in a PKCS#10 (native) or PKCS#7 (enveloped) format.
    /// </summary>
    /// <param name="path">Specifies the path to a file.</param>
    /// <returns>The type of the certificate request in the file.</returns>
    public static X509CertificateRequestType GetRequestFormat(String path) {
        return getRequestFormat(CryptBinaryConverter.CryptFileToBinary(path));
    }
    /// <summary>
    /// Gets the certificate request format. This method allows to determine whether the
    /// certificate request is encoded in a PKCS#10 (native) or PKCS#7 (enveloped) format.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array that represents certificate request.</param>
    /// <returns>The type of the certificate request in a byte array.</returns>
    public static X509CertificateRequestType GetRequestFormat(Byte[] rawData) {
        return getRequestFormat(rawData);
    }
}