using System;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Represents ADCS Certification Authority auto-discovery entry.
    /// </summary>
    public interface ICertConfigEntryD {
        /// <summary>
        /// Gets computer name.
        /// </summary>
        String ComputerName { get; }
        /// <summary>
        /// Gets common name of the server.
        /// </summary>
        String CommonName { get; }
        /// <summary>
        /// Gets display name of CA certificate.
        /// </summary>
        String DisplayName { get; }
        /// <summary>
        /// Gets description of CA server.
        /// </summary>
        String Description { get; }
        /// <summary>
        /// Gets organizational unit of CA certificate.
        /// </summary>
        String OrganizationUnit { get; }
        /// <summary>
        /// Gets the organization name of CA certificate.
        /// </summary>
        String Organization { get; }
        /// <summary>
        /// Gets state/province of CA certificate.
        /// </summary>
        String StateProvince { get; }
        /// <summary>
        /// Gets city or town of CA certificate.
        /// </summary>
        String Locality { get; }
        /// <summary>
        /// Gets country identifier of CA certificate.
        /// </summary>
        String Country { get; }
        /// <summary>
        /// Gets configuration string of CA certificate in a 'HostName\CA Certificate Name' form.
        /// </summary>
        String ConfigString { get; }
        /// <summary>
        /// Gets a set of flags that identify sources where current CA entry was found.
        /// </summary>
        CertConfigLocation Flags { get; }
        /// <summary>
        /// Gets the sanitized common name of the Certification Authority in a form as specified in
        /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
        /// </summary>
        String SanitizedName { get; }
        /// <summary>
        /// Gets the shortened common name of the Certification Authority in a form as specified in
        /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
        /// </summary>
        String ShortName { get; }
        /// <summary>
        /// Gets the sanitized and shorted common name of the Certification Authority in a form as specified in
        /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
        /// </summary>
        String SanitizedShortName { get; }
        /// <summary>
        /// An array of certificate enrollment Web service URLs for a specific CA configuration in the Active Directory.
        /// </summary>
        ICertConfigEnrollEndpointD[] WebEnrollmentServers { get; }
    }
}