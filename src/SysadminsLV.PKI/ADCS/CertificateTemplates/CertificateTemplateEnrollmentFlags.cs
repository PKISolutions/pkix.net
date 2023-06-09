using System;

namespace SysadminsLV.PKI.ADCS.CertificateTemplates;
/// <summary>
/// Defines certificate template enrollment flags.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum CertificateTemplateEnrollmentFlags {
    /// <summary>
    /// None.
    /// </summary>
    None                             = 0,
    /// <summary>
    /// This flag instructs the client and server to include a Secure/Multipurpose Internet Mail Extensions (S/MIME)
    /// certificate extension, as specified in <see href="http://tools.ietf.org/html/rfc4262">RFC4262</see>,
    /// in the request and in the issued certificate.
    /// </summary>
    IncludeSymmetricAlgorithms       = 0x00000001, // 1
    /// <summary>
    /// This flag instructs the CA to put all requests in a pending state.
    /// </summary>
    CAManagerApproval                = 0x00000002, // 2
    /// <summary>
    /// This flag instructs the CA to publish the issued certificate to the key recovery agent (KRA) container in Active Directory.
    /// </summary>
    KraPublish                       = 0x00000004, // 4
    /// <summary>
    /// This flag instructs clients and CA servers to append the issued certificate to the <strong>userCertificate</strong>
    /// attribute, as specified in <see href="http://tools.ietf.org/html/rfc4523">RFC4523</see>, on the user object
    /// in Active Directory.
    /// </summary>
    DsPublish                        = 0x00000008, // 8
    /// <summary>
    /// This flag instructs clients not to do autoenrollment for a certificate based on this template if the user's
    /// <strong>userCertificate</strong> attribute (specified in <see href="http://tools.ietf.org/html/rfc4523">RFC4523</see>)
    /// in Active Directory has a valid certificate based on the same template.
    /// </summary>
    AutoenrollmentCheckDsCert        = 0x00000010, // 16
    /// <summary>
    /// This flag instructs clients to perform autoenrollment for the specified template.
    /// </summary>
    Autoenrollment                   = 0x00000020, // 32
    /// <summary>
    /// This flag instructs clients to sign the renewal request using the private key of the existing certificate.
    /// </summary>
    ReenrollExistingCert             = 0x00000040, // 64
    /// <summary>
    /// This flag instructs the client to obtain user consent before attempting to enroll for a certificate that is based
    /// on the specified template.
    /// </summary>
    RequireUserInteraction           = 0x00000100, // 256
    /// <summary>
    /// This flag instructs the autoenrollment client to delete any certificates that are no longer needed based on the
    /// specific template from the local certificate storage.
    /// </summary>
    RemoveInvalidFromStore           = 0x00000400, // 1024
    /// <summary>
    /// This flag instructs the server to allow enroll on behalf of (<strong>EOBO</strong>) functionality.
    /// </summary>
    AllowEnrollOnBehalfOf            = 0x00000800, // 2048
    /// <summary>
    /// This flag instructs the server to not include revocation information and add the id-pkix-ocsp-nocheck extension,
    /// as specified in <see href="http://tools.ietf.org/html/rfc2560">RFC2560</see> section §4.2.2.2.1, to the certificate
    /// that is issued.
    /// <para><strong>Windows Server 2003</strong> - this flag is not supported.</para>
    /// </summary>
    IncludeOcspRevNoCheck            = 0x00001000, // 4096
    /// <summary>
    /// This flag instructs the client to reuse the private key for a smart card–based certificate renewal if it is unable
    /// to create a new private key on the card.
    /// <para><strong>Windows XP, Windows Server 2003</strong> - this flag is not supported.</para>
    /// </summary>
    ReuseKeyTokenFull                = 0x00002000, // 8192
    /// <summary>
    /// This flag instructs the server to not include revocation information in the issued certificate.
    /// <para><strong>Windows Server 2003, Windows Server 2008</strong> - this flag is not supported.</para>
    /// </summary>
    NoRevocationInformation          = 0x00004000, // 16384
    /// <summary>
    /// This flag instructs the server to include Basic Constraints extension in the end entity certificates.
    /// <para><strong>Windows Server 2003, Windows Server 2008</strong> - this flag is not supported.</para>
    /// </summary>
    BasicConstraintsInEndEntityCerts = 0x00008000, // 32768
    /// <summary>
    /// This flag instructs the CA to ignore the requirement for <strong>Enroll</strong> permissions on the template when
    /// processing renewal requests.
    /// <para><strong>Windows Server 2003, Windows Server 2008, Windows Server 2008 R2</strong> - this flag is not supported.</para>
    /// </summary>
    IgnoreEnrollOnReenrollment       = 0x00010000, // 65536
    /// <summary>
    /// This flag indicates that the certificate issuance policies to be included in the issued certificate come from the
    /// request rather than from the template. The template contains a list of all of the issuance policies that the request
    /// is allowed to specify; if the request contains policies that are not listed in the template, then the request is rejected.
    /// <para><strong>Windows Server 2003, Windows Server 2008, Windows Server 2008 R2</strong> - this flag is not supported.</para>
    /// </summary>
    IssuancePoliciesFromRequest      = 0x00020000, // 131072
    /// <summary>
    /// This flag instructs autoenrollment client to not renew certificate although the certificate meets all conditions
    /// for automatic renewal, i.e. initial automatic certificate enrollment is enabled and subsequent renewal is disabled.
    /// </summary>
    SkipAutoRenewal                  = 0x00040000,
    /// <summary>
    /// Instructs Enterprise CA to not include SID extension in issued certificates that use subject construction from Active Directory.
    /// More information in <see href="https://support.microsoft.com/kb/5014754">KB5014754</see>
    /// </summary>
    DoNotIncludeSidExtension         = 0x00080000
}