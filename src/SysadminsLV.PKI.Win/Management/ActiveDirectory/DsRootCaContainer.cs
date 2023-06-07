using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.PKI.Exceptions;

namespace SysadminsLV.PKI.Management.ActiveDirectory;
/// <summary>
/// Represents trusted Root CA certificate container in Active Directory. This container is used by domain members
/// to build certificate chains with trusted root CAs defined by organization.
/// </summary>
public class DsRootCaContainer : DsPkiCertContainer {
    const String dsObjectClass = "certificationAuthority";

    internal DsRootCaContainer() {
        ContainerType = DsContainerType.RootCA;
        BaseEntryPath = "CN=Certification Authorities";
        DsObjectClasses.Add(dsObjectClass);
        ReadChildren(new[] { DsCertificateType.CACertificate });
    }
    /// <summary>
    /// Adds CA certificate to RootCA entry in Active Directory.
    /// </summary>
    /// <param name="cert">Root CA certificate to add.</param>
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
        String containerName = GetContainerName(cert);
        var entry = new DsCertificateEntry(containerName, cert, DsCertificateType.CACertificate);
        return AddCertificateEntry(entry);
    }
    /// <summary>
    /// Removes CA certificate from a current RootCA container.
    /// </summary>
    /// <param name="entry">CA certificate to remove.</param>
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
            DirectoryEntry dsEntry = DirectoryEntry.Exists($"LDAP://CN={name},{DsPath}")
                ? new DirectoryEntry($"LDAP://CN={name},{DsPath}")
                // if no such entry exists, create it.
                : AddChild(null, $"CN={name}", dsObjectClass);
            // if we elected to delete empty entries --> check them
            if (forceDelete && CheckDelete(dsEntry, name)) {
                continue;
            }
            // write CA certificates
            dsEntry.Properties["cACertificate"].Clear();
            DsCertificateEntry[] caCerts = DsList[name].Where(x => x.CertificateType == DsCertificateType.CACertificate).ToArray();
            // cACertificate is mandatory attribute
            if (!caCerts.Any()) {
                dsEntry.Properties["cACertificate"].Add(new Byte[] { 0 });
            } else {
                foreach (DsCertificateEntry entry in caCerts) {
                    dsEntry.Properties["cACertificate"].Add(entry.Certificate.RawData);
                }
            }
            dsEntry.CommitChanges();
        }
        CleanupSave();
    }
}
