using System;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using PKI.CertificateServices;
using SysadminsLV.PKI.Dcom.Implementations;
using SysadminsLV.PKI.Management.CertificateServices;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents an Enterprise Certification Authority entry in Active Directory.
    /// </summary>
    public class DsCertEnrollServer {
        readonly PolicyEnrollEndpointUriCollection _cesUriCollection = new();

        internal DsCertEnrollServer(DirectoryEntry entry) {
            DistinguishedName = entry.Properties["distinguishedName"].Value?.ToString();
            Name = entry.Properties["cn"].Value?.ToString();
            DisplayName = entry.Properties["displayName"].Value?.ToString();
            ComputerName = entry.Properties["dNSHostName"].Value?.ToString();
            CertificateTemplates = (entry.Properties["certificateTemplates"].Value as Object[])?.Select(x => x.ToString()).ToArray();
            Byte[] certProp = entry.Properties["cACertificate"].Value as Byte[];
            if (certProp?.Length > 1) {
                Certificate = new X509Certificate2(certProp);
            }
            Flags = (DsEnrollServerFlag)Convert.ToInt32(entry.Properties["flags"].Value);
            if (entry.Properties.Contains("msPKI-Enrollment-Servers")) {
                Object enrollUri = entry.Properties["msPKI-Enrollment-Servers"].Value;

                if (enrollUri is Object[] uriArray) {
                    foreach (Object dsUri in uriArray) {
                        try {
                            var webUri = new PolicyEnrollEndpointUri(new CertConfigEnrollEndpointD(dsUri.ToString()));
                            _cesUriCollection.Add(webUri);
                        } catch { }
                    }
                } else {
                    try {
                        var webUri = new PolicyEnrollEndpointUri(new CertConfigEnrollEndpointD(enrollUri.ToString()));
                        _cesUriCollection.Add(webUri);
                    } catch { }
                }


                
            }
        }

        /// <summary>
        /// Gets the distinguished name of Enrollment Server entry.
        /// </summary>
        public String DistinguishedName { get; }
        /// <summary>
        /// Gets the common name of Certification Authority.
        /// </summary>
        public String Name { get; }
        /// <summary>
        /// Gets the display name of Certification Authority.
        /// </summary>
        public String DisplayName { get; }
        /// <summary>
        /// Gets the computer name where Certification Authority is installed.
        /// </summary>
        public String ComputerName { get; }
        /// <summary>
        /// Gets the Certification Authority certificate.
        /// </summary>
        public X509Certificate2 Certificate { get; }
        /// <summary>
        /// Gets an array of certificate templates supported by the Certification Authority. Each certificate template is referenced by
        /// its common name.
        /// </summary>
        public String[] CertificateTemplates { get; }
        /// <summary>
        /// Gets Enrollment Server directory services flags.
        /// </summary>
        public DsEnrollServerFlag Flags { get; }
        /// <summary>
        /// Gets a collection of Certificate Enrollment Web Service (CES) endpoint URIs.
        /// </summary>
        public PolicyEnrollEndpointUriCollection PolicyEnrollmentEndpoints => new(_cesUriCollection);

        /// <summary>
        /// Gets a Certification Authority object associated with the current Enrollment Services entry.
        /// </summary>
        /// <returns>Certification Authority object.</returns>
        public CertificateAuthority GetCertificateAuthority() {
            return CertificateAuthority.Connect(ComputerName);
        }
    }
}