using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Represents a wrapper interface for Microsoft
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/certadm/nn-certadm-icertadmin2">ICertAdmin2</see> COM interface.
    /// </summary>
    public interface ICertPropReaderD {
        /// <summary>
        /// Gets the the Certification Authority file version property.
        /// </summary>
        /// <returns>Certification Authority file version property.</returns>
        String GetFileVersionProperty();
        /// <summary>
        /// Gets the the Certification Authority product version property.
        /// </summary>
        /// <returns>Certification Authority product version property.</returns>
        String GetProductVersionProperty();
        /// <summary>
        /// Gets the number of exit modules registered on Certification Authority server.
        /// </summary>
        /// <returns>Number of exit modules registered on Certification Authority server.</returns>
        Int32 GetExitModuleCount();
        /// <summary>
        /// Gets the description of a specific exit module.
        /// </summary>
        /// <param name="index">
        /// Zero-based index of exit module. Value must be between 0 and a value returned by <see cref="GetExitModuleCount"/> minus one.
        /// </param>
        /// <returns>Description of a specific exit module.</returns>
        String GetExitModuleDescription(Int32 index);
        /// <summary>
        /// Gets the description of the active policy module.
        /// </summary>
        /// <returns>Description of the active policy module.</returns>
        String GetPolicyModuleDescription();
        /// <summary>
        /// Gets the common name of the Certification Authority.
        /// </summary>
        /// <returns>Common name of the Certification Authority.</returns>
        String GetCaName();
        /// <summary>
        /// Gets the sanitized common name of the Certification Authority.
        /// </summary>
        /// <returns>
        /// Sanitized common name of the Certification Authority in a form as specified in
        /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
        /// </returns>
        String GetSanitizedCaName();
        /// <summary>
        /// Gets the UNC path that is used as a shared folder for the Certification Authority.
        /// </summary>
        /// <returns>
        /// UNC path that is used as a shared folder for the Certification Authority.
        /// </returns>
        String GetSharedFolderPath();
        /// <summary>
        /// Gets the name of the parent of the Certification Authority.
        /// </summary>
        /// <returns>Name of the parent of the Certification Authority.</returns>
        String GetParentCA();
        /// <summary>
        /// Get the type of the Certification Authority.
        /// </summary>
        /// <returns>Type of the Certification Authority.</returns>
        AdcsPropCaType GetCaType();
        /// <summary>
        /// Gets the count of signature certificates on the Certification Authority.
        /// </summary>
        /// <returns>Count of signature certificates on the Certification Authority.</returns>
        Int32 GetCaCertificateCount();
        /// <summary>
        /// Gets a specified signing certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>ASN.1-encoded byte array that represents an X.509 certificate.</returns>
        Byte[] GetCaCertificate(Int32 index);
        /// <summary>
        /// Gets the most recent signing certificate.
        /// </summary>
        /// <returns>ASN.1-encoded byte array that represents an X.509 certificate.</returns>
        Byte[] GetLatestCaCertificate();
        /// <summary>
        /// Gets a particular signing certificate and its complete chain.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>
        /// ASN.1-encoded signed PKCS#7 message that contains Certification Authority and other certificates in the chain up to self-signed root
        /// certificate.
        /// </returns>
        Byte[] GetCaCertificateChain(Int32 index);
        /// <summary>
        /// Gets the most recent signing certificate and its complete chain.
        /// </summary>
        /// <returns>
        /// ASN.1-encoded signed PKCS#7 message that contains Certification Authority and other certificates in the chain up to self-signed root
        /// certificate.
        /// </returns>
        Byte[] GetLatestCaCertificateChain();
        /// <summary>
        /// Gets the count of exchange (key archival encryption) certificates on the Certification Authority.
        /// </summary>
        /// <returns>Count of exchange certificates on the Certification Authority.</returns>
        Int32 GetExchangeCertificateCount();
        /// <summary>
        /// Gets the Certification Authority exchange (key archival encryption) certificate.
        /// </summary>
        /// <returns>ASN.1-encoded byte array that represents an X.509 certificate.</returns>
        Byte[] GetExchangeCertificate();
        /// <summary>
        /// Gets the Certification Authority exchange certificate and its complete chain.
        /// </summary>
        /// <returns>
        /// ASN.1-encoded signed PKCS#7 message that contains Certification Authority exchange and other certificates in the chain up to self-signed
        /// root certificate.
        /// </returns>
        Byte[] GetExchangeCertificateChain();
        /// <summary>
        /// Gets a particular base certificate revocation list.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>ASN.1-encoded byte array that represents an X.509 certificate revocation list.</returns>
        Byte[] GetBaseCrl(Int32 index);
        /// <summary>
        /// Gets a base certificate revocation list for the most recent Certification Authority signing certificate.
        /// </summary>
        /// <returns>ASN.1-encoded byte array that represents an X.509 certificate revocation list.</returns>
        Byte[] GetLatestCertBaseCrl();
        /// <summary>
        /// Gets a particular delta certificate revocation list.
        /// </summary>
        /// <param name="index"></param>
        /// <returns>ASN.1-encoded byte array that represents an X.509 certificate revocation list.</returns>
        Byte[] GetDeltaCrl(Int32 index);
        /// <summary>
        /// Gets a delta certificate revocation list for the most recent Certification Authority signing certificate.
        /// </summary>
        /// <returns>
        /// ASN.1-encoded byte array that represents an X.509 certificate revocation list. If delta certificate revocation list is not enabled,
        /// the method returns null.
        /// </returns>
        Byte[] GetLatestCertDeltaCrl();
        /// <summary>
        /// Gets the disposition status of a particular Certification Authority signing certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>Disposition status of Certification Authority signing certificate.</returns>
        AdcsPropCertState GetCaCertState(Int32 index);
        /// <summary>
        /// Gets the status of signing certificate used to publish CRLs.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>Certification Authority signing certificate state.</returns>
        AdcsPropCrlState GetCrlState(Int32 index);
        /// <summary>
        /// Gets the FQDN of the server that hosts the Certification Authority.
        /// </summary>
        /// <returns>Certification Authority server host FQDN.</returns>
        String GetDnsName();
        /// <summary>
        /// Gets the information whether the role separation feature is enabled on the Certification Authority.
        /// </summary>
        /// <returns><strong>True</strong> if role separation feature is enabled, otherwise <strong>False</strong>.</returns>
        Boolean IsRoleSeparationEnabled();
        /// <summary>
        /// Gets the number of KRAs are required to be used when archiving a private key on the Certification Authority.
        /// </summary>
        /// <returns>Number of KRAs.</returns>
        Int32 GetKraCertUsedCount();
        /// <summary>
        /// Gets the total number of KRAs registered and available for the Certification Authority.
        /// </summary>
        /// <returns>Number of total KRAs registered and available for the Certification Authority.</returns>
        Int32 GetKraCertCount();
        /// <summary>
        /// Gets a particular KRA certificate
        /// </summary>
        /// <param name="index">
        /// A zero-based index of KRA certificate. Index must be between 0 and a value returned by <see cref="GetKraCertCount"/> minus one.
        /// </param>
        /// <returns>ASN.1-encoded byte array that represents an X.509 certificate.</returns>
        Byte[] GetKraCertificate(Int32 index);
        /// <summary>
        /// Gets the state of a particular KRA certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of KRA certificate. Index must be between 0 and a value returned by <see cref="GetKraCertCount"/> minus one.
        /// </param>
        /// <returns>Status of KRA certificate.</returns>
        AdcsPropKraCertStatus GetKraCertState(Int32 index);
        /// <summary>
        /// Gets the information whether the operating system that hosts the Certification Authority is an advanced server.
        /// </summary>
        /// <returns><strong>True</strong> if Certification Authority operating system is "Advanced SKU", otherwise <strong>False</strong>.</returns>
        Boolean IsAdvancedServer();
        /// <summary>
        /// Returns a list of certificate templates assigned to Enterprise Certification Authority.
        /// </summary>
        /// <returns>
        ///     A two-dimensional string array. The size of the first dimension equals to a number of certificate templates assigned to
        ///     Certification Authority. The size of the second dimension is 2. First element of second dimension contains certificate
        ///     template common name. Second element of second dimension contains certificate template OID.
        /// </returns>
        String[,] GetCaTemplates();
        /// <summary>
        /// Gets the publishing status of a particular base certificate revocation list.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>Base certificate revocation list publishing status.</returns>
        AdcsPropCrlPublishState GetBaseCrlPublishStatus(Int32 index);
        /// <summary>
        /// Gets the publishing status of the most recent base certificate revocation list.
        /// </summary>
        /// <returns>Base certificate revocation list publishing status.</returns>
        AdcsPropCrlPublishState GetLatestCertBaseCrlPublishStatus();
        /// <summary>
        /// Gets the publishing status of a particular delta certificate revocation list.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>Delta certificate revocation list publishing status.</returns>
        AdcsPropCrlPublishState GetDeltaCrlPublishStatus(Int32 index);
        /// <summary>
        /// Gets the publishing status of the most recent delta certificate revocation list.
        /// </summary>
        /// <returns>Delta certificate revocation list publishing status.</returns>
        AdcsPropCrlPublishState GetLatestCertDeltaCrlPublishStatus();
        /// <summary>
        /// Gets a particular Certification Authority signing certificate and its complete chain, including certificate revocation lists.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>
        /// ASN.1-encoded signed PKCS#7 message that contains Certification Authority signing certificate and other certificates in the chain up to
        /// a self-signed root certificate and certificate revocation lists.
        /// </returns>
        Byte[] GetCaCertChainAndCrl(Int32 index);
        /// <summary>
        /// Gets the latest Certification Authority signing certificate and its complete chain, including certificate revocation lists.
        /// </summary>
        /// <returns>
        /// ASN.1-encoded signed PKCS#7 message that contains Certification Authority signing certificate and other certificates in the chain up to
        /// a self-signed root certificate and certificate revocation lists.
        /// </returns>
        Byte[] GetLatestCaCertChainAndCrl();
        /// <summary>
        /// Gets the latest Certification Authority exchange (key encryption) certificate and its complete chain, including certificate revocation lists.
        /// </summary>
        /// <returns>
        /// ASN.1-encoded signed PKCS#7 message that contains Certification Authority encryption certificate and other certificates in the chain up to
        /// a self-signed root certificate and certificate revocation lists.
        /// </returns>
        Byte[] GetLatestExchangeCertChainAndCrl();
        /// <summary>
        /// Gets the Win32 HRESULT status of a particular Certification Authority signing certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>0 (ERROR_SUCCESS) if the certificate is valid. A non-zero value means error status </returns>
        Int32 GetCaCertStatusCode(Int32 index);
        /// <summary>
        /// Gets the Win32 HRESULT status of a particular Certification Authority signing certificate.
        /// </summary>
        /// <returns>0 (ERROR_SUCCESS) if the certificate is valid. A non-zero value means error status </returns>
        Int32 GetLatestCaCertStatusCode();
        /// <summary>
        /// Gets a particular forward cross certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 1 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus two.
        /// </param>
        /// <returns>ASN.1-encoded byte array that represents an X.509 certificate.</returns>
        Byte[] GetForwardCrossCert(Int32 index);
        /// <summary>
        /// Gets a particular backward cross certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 1 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>ASN.1-encoded byte array that represents an X.509 certificate.</returns>
        Byte[] GetBackwardCrossCert(Int32 index);
        /// <summary>
        /// Gets the status of a particular forward cross certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus two.
        /// </param>
        /// <returns>Status of forward cross certificate.</returns>
        AdcsPropCertState GetForwardCrossCertState(Int32 index);
        /// <summary>
        /// Gets the status of a particular backward cross certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 1 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>Status of backward cross certificate.</returns>
        AdcsPropCertState GetBackwardCrossCertState(Int32 index);
        /// <summary>
        /// Gets the revisions on the Certification Authority signing certificate
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>
        /// A 32-bit unsigned integer value, where the 16 most significant bits denote key index and 16 least significant bits denote certificate index.
        /// </returns>
        Int32 GetCaVersion(Int32 index);
        /// <summary>
        /// Gets the sanitized and shortened common name of the Certification Authority.
        /// </summary>
        /// <returns>
        /// Sanitized common name of the Certification Authority in a form as specified in
        /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
        /// </returns>
        String GetSanitizedShortCommonName();
        /// <summary>
        /// Gets the list of certificate revocation list distribution points (CDPs) URLs to include in issued certificates, for a particular
        /// Certification Authority certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>An array of URLs.</returns>
        String[] GetCdpURLs(Int32 index);
        /// <summary>
        /// Gets the list of certificate revocation list distribution points (CDPs) URLs to include in issued certificates, for the most recent
        /// Certification Authority certificate.
        /// </summary>
        /// <returns>An array of URLs.</returns>
        String[] GetLatestCertCdpURLs();
        /// <summary>
        /// Gets the list of authority information access (AIA) URLs to include in issued certificates, for a particular Certification Authority
        /// certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>An array of URLs.</returns>
        String[] GetAiaURLs(Int32 index);
        /// <summary>
        /// Gets the list of authority information access (AIA) URLs to include in issued certificates, for the most recent Certification Authority
        /// certificate.
        /// </summary>
        /// <returns>An array of URLs.</returns>
        String[] GetLatestCertAiaURLs();
        /// <summary>
        /// Gets the list of Online Certificate Status Protocol (OCSP) URLs to include in issued certificates, for a particular Certification Authority
        /// certificate.
        /// </summary>
        /// <param name="index">
        /// A zero-based index of Certification Authority certificate. Index must be between 0 and a value returned by <see cref="GetCaCertificateCount"/>
        /// minus one.
        /// </param>
        /// <returns>An array of URLs.</returns>
        String[] GetOcspURLs(Int32 index);
        /// <summary>
        /// Gets the list of Online Certificate Status Protocol (OCSP) URLs to include in issued certificates, for the most recent Certification Authority
        /// certificate.
        /// </summary>
        /// <returns>An array of URLs.</returns>
        String[] GetLatestCertOcspURLs();
        /// <summary>
        /// Gets the locale of the Certification Authority.
        /// </summary>
        /// <returns>A locale string in a format specified in <see href="https://tools.ietf.org/html/rfc4646">RFC 4646</see>.</returns>
        String GetLocaleName();
        /// <summary>
        /// Gets a collection of relative distinguished name (RDN) attributes used by Certification Authority to order attributes in certificate subject.
        /// </summary>
        /// <returns></returns>
        OidCollection GetSubjectTemplateOIDs();
    }
}