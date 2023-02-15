namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Defines the list of possible certificate context properties when the certificate is placed in the
/// Certificate Store.
/// </summary>
public enum X509CertificatePropertyType {
    /// <summary>
    /// No property is identified.
    /// </summary>
    None = 0,
    /// <summary>
    /// The handle of the private key associated with the certificate.
    /// </summary>
    Handle = 1,
    /// <summary>
    /// Information about a CSP key container or a Cryptography API: Next Generation (CNG) key.
    /// </summary>
    ProviderInfo = 2,
    /// <summary>
    /// SHA-1 hash value of the certificate
    /// </summary>
    SHA1Hash = 3,
    /// <summary>
    /// MD5 hash value of the certificate
    /// </summary>
    MD5Hash = 4,
    /// <summary>
    /// Hash of the certificate created by using the default hashing algorithm. The default algorithm is
    /// currently SHA-1.
    /// </summary>
    DefaultHash = 3,
    /// <summary>
    /// Information necessary to retrieve a key, including the CSP or key service provider (KSP) handle and a
    /// value that indicates whether the key is used for signing or encryption.
    /// </summary>
    KeyContext = 5,
    /// <summary>
    /// Value that identifies whether the key is used for signing or for encryption and whether the key is
    /// associated with a CNG Key Storage Provider.
    /// </summary>
    KeySpec = 6,
    /// <summary>
    /// Subject's public key hash in reversed order.
    /// </summary>
    PublicKeyHashReversed = 8,
    /// <summary>
    /// A collection of enabled enhanced key usages.
    /// </summary>
    EnhancedKeyUsage = 9,
    /// <summary>
    /// Locations at which next certificate trust list (CTL) will be published.
    /// </summary>
    CTLNextUpdateLocation = 10,
    /// <summary>
    /// Display name for the certificate.
    /// </summary>
    FriendlyName = 11,
    /// <summary>
    /// The file name that contains the private key associated with the certificate's public key.
    /// </summary>
    PvkFile = 12,
    /// <summary>
    /// Description of the certificate
    /// </summary>
    Description = 13,
    /// <summary>
    /// Information that indicates whether the object is write-allowed.
    /// </summary>
    AccessState = 14,
    /// <summary>
    /// SHA-1 or MD5 hash of the signature. Exact hashing algorithm is determined by a hash value length.
    /// </summary>
    SignatureHash = 15,
    /// <summary>
    /// Encoded smart card data.
    /// </summary>
    SmartCardData = 16,
    /// <summary>
    /// A boolean value that indicates that the certificate is archived and excluded from enumerations.
    /// </summary>
    Archived = 19,
    /// <summary>
    /// SHA-1 hash of the subject's public key.
    /// </summary>
    SubjectKeyIdentifier = 20,
    /// <summary>
    /// Certificate template name for which the certificate has been auto enrolled.
    /// </summary>
    AutoenrollmentTemplateName = 21,
    /// <summary>
    /// Public key algorithm parameters.
    /// </summary>
    PublicKeyParameters = 22,
    /// <summary>
    /// Location of the cross certificates.
    /// </summary>
    CrossCertificateDistributionPoints = 23,
    /// <summary>
    /// MD5 hash of the issuer's public key.
    /// </summary>
    IssuerPublicKeyMD5Hash = 24,
    /// <summary>
    /// MD5 hash of the subject's public key.
    /// </summary>
    PublicKeyMD5Hash = 25,
    /// <summary>
    /// Enrollment information of the pending request that contains RequestID, CADNSName, CAName, and DisplayName.
    /// </summary>
    EnrollmentInfo = 26,
    /// <summary>
    /// The time when the certificate was added to the certificate store.
    /// </summary>
    InsertTimeStamp = 27,
    /// <summary>
    /// MD5 hash of the issuer's serial number.
    /// </summary>
    IssuerSerialNumberMD5Hash = 28,
    /// <summary>
    /// MD5 hash of the subject name.
    /// </summary>
    SubjectNameMD5Hash = 29,
    /// <summary>
    /// Extended error status text.
    /// </summary>
    StatusInfo = 30,
    /// <summary>
    /// The hash of the renewed certificate.
    /// </summary>
    RenewalCertificateHash = 64,
    /// <summary>
    /// SHA-1 hash of the archived certificate and which was replaced by a current certificate.
    /// </summary>
    ArchivedKeyHash = 65,
    /// <summary>
    /// An encoded stapled OCSP response for this certificate.
    /// </summary>
    OcspResponse = 70,
    /// <summary>
    /// DNS computer name for the origination of the certificate context request
    /// </summary>
    RequestOriginatorMachine = 71,
    /// <summary>
    /// A string that represents enrollment service location.
    /// </summary>
    SourceLocation = 72,
    /// <summary>
    /// A string that represents enrollment service URL.
    /// </summary>
    SourceUrl = 73,
    /// <summary>
    /// Prefix of the OCSP response cache entry.
    /// </summary>
    OcspCachePrefix = 75,
    /// <summary>
    /// A collection of Microsoft Root Program certificate policies used to issue Extended Validation (EV)
    /// certificates.
    /// </summary>
    RootProgramCertificatePolicies = 83,
    /// <summary>
    /// Certificate Enrollment Web Services information used for certificate enrollment.
    /// </summary>
    CEPEnrollmentInfo = 87,
    /// <summary>
    /// CNG signature hash algorithm. For example, 'RSA/SHA1'.
    /// </summary>
    CNGSignatureHashAlgorithm = 89,
    /// <summary>
    /// Subject's public key length in bits.
    /// </summary>
    PublicKeyLength = 92,
    /// <summary>
    /// Subject's CNG public key length in bits.
    /// </summary>
    PublicKeyCngLength = 93,
    /// <summary>
    /// Indicates that no certificate expiration notification is logged in the Event Viewer.
    /// </summary>
    NoExpireNotification = 97
}