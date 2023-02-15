using System;
using System.Security.Cryptography.X509Certificates;
using PKI.Exceptions;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents NTAuth certificate store in Active Directory. This store contains CA certificates that are
    /// eligible to issue client authentication and logon certificates and perform client key archival on CA server.
    /// </summary>
    public sealed class DsNTAuthContainer : DsPkiCertContainer {
        const String dsObjectClass = "certificationAuthority";

        /// <summary>
        /// Initializes a new instance of <strong>DsNTAuthContainer</strong> object.
        /// </summary>
        internal DsNTAuthContainer() {
            ContainerType = DsContainerType.NTAuth;
            BaseEntryPath = "CN=NTAuthCertificates";
            DsObjectClasses.Add(dsObjectClass);
            ReadChildren(new[] { DsCertificateType.CACertificate });

        }

        /// <summary>
        /// Adds CA certificate to NTAuth entry in Active Directory.
        /// </summary>
        /// <param name="cert">CA certificate to add.</param>
        /// <exception cref="UninitializedObjectException">
        /// <strong>cert</strong> parameter is not valid X.509 certificate object.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <strong>cert</strong> parameter is null.
        /// </exception>
        /// <inheritdoc cref="DsPkiCertContainer.AddCertificateEntry" section="returns|remarks/*"/>
        public Boolean AddCertificate(X509Certificate2 cert) {
            if (cert == null) {
                throw new ArgumentNullException(nameof(cert));
            }
            if (cert.RawData == null) {
                throw new UninitializedObjectException();
            }
            var entry = new DsCertificateEntry("NTAuth", cert, DsCertificateType.CACertificate);
            return AddCertificateEntry(entry);
        }
        /// <summary>
        /// Removes CA certificate from a current NTAuth container.
        /// </summary>
        /// <param name="entry">CA certificate to remove</param>
        /// <inheritdoc cref="DsPkiCertContainer.RemoveCertificateEntry" section="exception|returns|remarks/*"/>
        public Boolean RemoveCertificate(DsCertificateEntry entry) {
            return RemoveCertificateEntry(entry);
        }


        /// <inheritdoc />
        public override void SaveChanges(Boolean forceDelete) {
            BaseEntry.Properties["cACertificate"].Clear();
            foreach (DsCertificateEntry cert in DsList["NTAuth"]) {
                BaseEntry.Properties["cACertificate"].Add(cert.Certificate.RawData);
            }
            BaseEntry.CommitChanges();
            CleanupSave();
        }
    }
}
