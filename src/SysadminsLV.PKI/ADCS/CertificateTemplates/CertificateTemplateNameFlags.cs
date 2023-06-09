using System;

namespace SysadminsLV.PKI.ADCS.CertificateTemplates;
/// <summary>
/// Defines flags that determine how certificate subject is constructed.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum CertificateTemplateNameFlags {
    /// <summary>
    /// This flag instructs the client to supply subject information in the certificate request.
    /// </summary>
    EnrolleeSuppliesSubject          = 0x00000001, // 1
    /// <summary>
    /// This flag instructs the client to reuse values of subject name and alternative subject name extensions from an existing valid
    /// certificate when creating a certificate renewal request.
    /// <para><strong>Windows Server 2003, Windows Server 2008</strong> - this flag is not supported.</para>
    /// </summary>
    OldCertSuppliesSubjectAndAltName = 0x00000008, // 8
    /// <summary>
    /// This flag instructs the client to supply subject alternate name information in the certificate request.
    /// </summary>
    EnrolleeSuppluiesAltSubject      = 0x00010000, // 65536
    /// <summary>
    /// This flag instructs the CA to add the value of the requester FQDN and NetBIOS name to the Subject Alternative Name extension
    /// of the issued certificate.
    /// </summary>
    AltSubjectRequireDomainDNS       = 0x00400000, // 4194304
    /// <summary>
    /// This flag instructs the CA to add the value of the requester Service Principal name to the Subject Alternative Name extension
    /// of the issued certificate.
    /// </summary>
    AltSubjectRequireSPN             = 0x00800000, // 8388608
    /// <summary>
    /// This flag instructs the CA to add the value of the objectGUID attribute from the requester user object in Active Directory to the
    /// Subject Alternative Name extension of the issued certificate.
    /// </summary>
    AltSubjectRequireDirectoryGUID   = 0x01000000, // 16777216
    /// <summary>
    /// This flag instructs the CA to add the value of the UPN attribute from the requester user object in Active Directory to the
    /// Subject Alternative Name extension of the issued certificate.
    /// </summary>
    AltSubjectRequireUPN             = 0x02000000, // 33554432
    /// <summary>
    /// This flag instructs the CA to add the value of the e-mail attribute from the requester user object in Active Directory to the
    /// Subject Alternative Name extension of the issued certificate.
    /// </summary>
    AltSubjectRequireEmail           = 0x04000000, // 67108864
    /// <summary>
    /// This flag instructs the CA to add the value obtained from the DNS attribute of the requester user object in Active Directory to the
    /// Subject Alternative Name extension of the issued certificate.
    /// </summary>
    AltSubjectRequireDNS             = 0x08000000, // 134217728
    /// <summary>
    /// This flag instructs the CA to add the value obtained from the DNS attribute of the requester user object in Active Directory as the
    /// CN in the subject of the issued certificate.
    /// </summary>
    SubjectRequireDNSasCN            = 0x10000000, // 268435456
    /// <summary>
    /// This flag instructs the CA to add the value of the e-mail attribute from the requester user object in Active Directory as the
    /// subject of the issued certificate.
    /// </summary>
    SubjectRequireEmail              = 0x20000000, // 536870912
    /// <summary>
    /// This flag instructs the CA to set the subject name to the requester CN from Active Directory.
    /// </summary>
    SubjectRequireCommonName         = 0x40000000, // 1073741824
    /// <summary>
    /// This flag instructs the CA to set the subject name to the requester distinguished name (DN) from Active Directory.
    /// </summary>
    SubjectRequireDirectoryPath      = unchecked((Int32)0x80000000)  // -2147483648
}