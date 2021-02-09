using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PKI.Exceptions;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents key recovery agent (KRA) store in Active Directory. This container is used by Microsoft CA server
    /// to locate key recovery agent certificates when implementing key archival functionality.
    /// </summary>
    public sealed class DsKraContainer : DsPkiCertContainer {
        const String dsObjectClass = "msPKI-PrivateKeyRecoveryAgent";

        internal DsKraContainer() {
            ContainerType = DsContainerType.KRA;
            BaseEntryPath = "CN=KRA";
            DsObjectClasses.Add(dsObjectClass);
            ReadChildren(new[] { DsCertificateType.UserCertificate});
        }
        
        static Boolean validateConstraints(X509Certificate2 cert) {
            // check if KRA certificate is trusted, not revoked and is valid for KRA purpose.
            var chain = new X509Chain(true);
            Boolean status = chain.Build(cert);
            if (status && cert.Version < 3) {
                return true;
            }
            if (status && cert.Version == 3) {
                var ext = (X509EnhancedKeyUsageExtension)cert.Extensions[X509ExtensionOid.EnhancedKeyUsage];
                if (ext != null) {
                    foreach (Oid oid in ext.EnhancedKeyUsages) {
                        if (oid.Value == "1.3.6.1.4.1.311.21.6") {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Adds key recovery agent (KRA) certificate to Active Directory.
        /// </summary>
        /// <param name="cert">Key recovery agent certificate to add.</param>
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
            if (!validateConstraints(cert)) {
                return false;
            }
            String containerName = GetContainerName(cert);
            var entry = new DsCertificateEntry(containerName, cert, DsCertificateType.UserCertificate);
            return AddCertificateEntry(entry);
        }
        /// <summary>
        /// Removes KRA certificate from the current KRA container.
        /// </summary>
        /// <param name="entry">CA certificate to remove</param>
        /// <inheritdoc cref="DsPkiCertContainer.RemoveCertificateEntry" section="exception|returns|remarks/*"/>
        public Boolean RemoveCertificate(DsCertificateEntry entry) {
            return RemoveCertificateEntry(entry);
        }

        /// <inheritdoc />
        public override void SaveChanges(Boolean forceDelete) {
            if (!IsModified) { return; }
            // this list contains only entries we need to update.
            IEnumerable<String> namesToProcess = GetUpdateList();
            foreach (String name in namesToProcess) {
                // if no such entry exists, create it.
                DirectoryEntry dsEntry = DirectoryEntry.Exists($"LDAP://CN={name},{DsPath}")
                    ? new DirectoryEntry($"LDAP://CN={name},{DsPath}")
                    : AddChild(null, $"CN={name}", dsObjectClass);
                // if we elected to delete empty entries --> check them
                if (forceDelete && CheckDelete(dsEntry, name)) {
                    continue;
                }
                // write certificates certificates
                dsEntry.Properties["userCertificate"].Clear();
                foreach (DsCertificateEntry entry in DsList[name]) {
                    dsEntry.Properties["userCertificate"].Add(entry.Certificate.RawData);
                }
            }
            CleanupSave();
        }
    }
}
