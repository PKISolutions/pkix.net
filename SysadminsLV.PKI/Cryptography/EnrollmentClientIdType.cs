namespace SysadminsLV.PKI.Cryptography; 

/// <summary>
/// Defines the enumeration of certificate request originator.
/// </summary>
public enum EnrollmentClientIdType {
    /// <summary>
    /// No client identifier is specified.
    /// </summary>
    ClientIdNone			= 0,
    /// <summary>
    /// Specifies the Certificate Enrollment Control that is available on Windows Server 2003.
    /// </summary>
    ClientIdXEnroll2003		= 1,
    /// <summary>
    /// Specifies the autoenrollment that is available on Windows Server 2003.
    /// </summary>
    ClientIdAutoEnroll2003	= 2,
    /// <summary>
    /// Specifies the Certificate Request Wizard that is available on Windows Server 2003.
    /// </summary>
    ClientIdWizard2003		= 3,
    /// <summary>
    /// Specifies the Certreq.exe command-line tool that is available on Windows Server 2003.
    /// </summary>
    ClientIdCertReq2003		= 4,
    /// <summary>
    /// Specifies the default certificate request object that is available starting with Windows Vista.
    /// This is represented by the IX509CertificateRequest interface and is the default value if the client
    /// ID is not set by the caller.
    /// </summary>
    ClientIdDefaultRequest	= 5,
    /// <summary>
    /// Specifies the autoenrollment that is available starting with Windows Vista.
    /// </summary>
    ClientIdAutoEnroll		= 6,
    /// <summary>
    /// Specifies the Certificate Request Wizard that is available starting with Windows Vista.
    /// </summary>
    ClientIdRequestWizard	= 7,
    /// <summary>
    /// Specifies the Enroll-On-Behalf-Of (EOBO) Wizard that is available starting with Windows Vista.
    /// </summary>
    ClientIdEOBO			= 8,
    /// <summary>
    /// Specifies the Certreq.exe command-line tool that is available starting with Windows Vista.
    /// </summary>
    ClientIdCertReq			= 9,
    /// <summary>
    /// This value is not supported.
    /// </summary>
    ClientIdTest			= 10,
    /// <summary>
    /// This is the base value for custom applications.
    /// </summary>
    ClientIdUserStart		= 1000,

}