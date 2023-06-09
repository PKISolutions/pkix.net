using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.PKI.Exceptions;

namespace SysadminsLV.PKI.Management.ActiveDirectory;
/// <summary>
/// Represents intermediate CA certificate container in Active Directory. This container is used by domain members
/// to build certificate chains with CAs defined by organization. In addition, this container stores
/// cross-certificates when organization establishes a qualified trust with other organizations.
/// </summary>
public class DsAiaContainer : DsPkiCertContainer {
    const String dsObjectClass = "certificationAuthority";

    internal DsAiaContainer() {
        ContainerType = DsContainerType.AIA;
        BaseEntryPath = "CN=AIA";
        DsObjectClasses.Add(dsObjectClass);
        ReadChildren(new[] { DsCertificateType.CACertificate, DsCertificateType.CrossCertificate });
    }
    /// <summary>
    /// Adds CA certificate to AIA entry as CA certificate or cross-certificate. The type is determined by <strong>type</strong>
    /// parameter.
    /// <para>
    /// <strong>Note:</strong> 'userCertificate' type is not supported by this method.
    /// </para>
    /// </summary>
    /// <param name="cert">CA certificate to add.</param>
    /// <param name="type">Certificate type. Can be either 'CACertificate' or 'CrossCertificate'.</param>
    /// <exception cref="ArgumentException">
    /// specified certificate type is not valid.
    /// </exception>
    /// <exception cref="UninitializedObjectException">
    /// <strong>cert</strong> parameter is not valid X.509 certificate object.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <strong>cert</strong> parameter is null.
    /// </exception>
    /// <inheritdoc cref="DsPkiCertContainer.AddCertificateEntry" section="returns|remarks/*"/>
    public Boolean AddCertificate(X509Certificate2 cert, DsCertificateType type) {
        if (cert == null) {
            throw new ArgumentNullException(nameof(cert));
        }
        if (cert.RawData == null) {
            throw new UninitializedObjectException();
        }
        if (type == DsCertificateType.UserCertificate) {
            throw new ArgumentException("Specified type is not supported.");
        }
        String containerName = GetContainerName(cert);
        var entry = new DsCertificateEntry(containerName, cert, type);
        return AddCertificateEntry(entry);
    }
    /// <summary>
    /// Removes CA certificate from a current AIA container.
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
            // write cross-certificates
            dsEntry.Properties["crossCertificatePair"].Clear();
            foreach (DsCertificateEntry entry in DsList[name].Where(x => x.CertificateType == DsCertificateType.CrossCertificate)) {
                dsEntry.Properties["crossCertificatePair"].Add(entry.Certificate.RawData);
            }
            dsEntry.CommitChanges();
        }
        CleanupSave();
    }
}
