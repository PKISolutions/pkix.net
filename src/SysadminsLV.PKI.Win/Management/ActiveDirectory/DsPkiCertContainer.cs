using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Management.ActiveDirectory;

/// <summary>
/// Represents a base class for certificate-based containers in Active Directory. This class implements common
/// operations associated with certificate-based container management.
/// </summary>
/// <remarks>This class is abstract and cannot be instantiated.</remarks>
public abstract class DsPkiCertContainer : DsPkiContainer {
    readonly ISet<DsCertificateEntry> _list = new HashSet<DsCertificateEntry>();
    readonly ISet<String> _toBeAdded = new HashSet<String>();
    readonly ISet<String> _toBeRemoved = new HashSet<String>();

    /// <summary>
    /// Gets an array of certificates stored in the current container.
    /// </summary>
    public DsCertificateEntry[] Certificates => _list.OrderBy(x => x.Name).ToArray();
    /// <summary>
    /// Gets internal list of all certificates in the current container grouped by DS object name.
    /// </summary>
    protected IDictionary<String, List<DsCertificateEntry>> DsList { get; } = new Dictionary<String, List<DsCertificateEntry>>(StringComparer.OrdinalIgnoreCase);
    /// <summary>
    /// Gets an unordered collection of supported by inheritors DS object classes.
    /// </summary>
    protected ISet<String> DsObjectClasses { get; } = new HashSet<String>(StringComparer.OrdinalIgnoreCase);

    // reads certificates of specified type from specified DS object.
    List<DsCertificateEntry> readCertsFromDsAttribute(DirectoryEntry entry, String key, DsCertificateType type) {
        String attribute;
        switch (type) {
            case DsCertificateType.CACertificate:
                attribute = "cACertificate";
                break;
            case DsCertificateType.CrossCertificate:
                attribute = "crossCertificatePair";
                break;
            case DsCertificateType.UserCertificate:
                attribute = "userCertificate";
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(type), type, null);
        }

        Byte[][] rawData = GetEntryProperty<Byte[]>(entry, attribute);
        // x.Length > 1 is necessary, because empty mandatory value contains a 1 byte element.
        return rawData.Where(x => x.Length > 1)
            .Select(bytes => new DsCertificateEntry(key, new X509Certificate2(bytes), type))
            .ToList();
    }
    // generates DS object name from X.500 name. If name is empty, an SHA-1 hash value of empty name is used.
    static String generateContainerName(X500DistinguishedName name) {
        X500RdnAttributeCollection tokens = name.GetRdnAttributes();
        // if subject is empty, calculate SHA1 hash over subject name's raw data (48, 0)
        if (tokens.Count == 0) {
            var sb = new StringBuilder();
            using (var hasher = SHA1.Create()) {
                foreach (Byte b in hasher.ComputeHash(name.RawData)) {
                    sb.AppendFormat("{0:x2}", b);
                }
            }
            return sb.ToString();
        }
        return DsUtils.GetSanitizedName(tokens[0].Value);
    }

    /// <summary>
    /// Reads specified types of certificates from the current container.
    /// </summary>
    /// <param name="certTypes">Specifies a collection of certificate types to read.</param>
    protected void ReadChildren(DsCertificateType[] certTypes) {
        var entries = new List<DirectoryEntry>();
        // handle NTAuth container, because it doesn't have children.
        if (ContainerType == DsContainerType.NTAuth) {
            foreach (DirectoryEntry child in BaseEntry.Parent.Children) {
                entries.Add(child);
            }
        } else {
            foreach (DirectoryEntry child in BaseEntry.Children) {
                entries.Add(child);
            }
        }
        foreach (DirectoryEntry child in entries) {
            // read only entries of specified DS object class
            if (!DsObjectClasses.Contains(child.SchemaClassName)) {
                continue;
            }
            String key = ContainerType == DsContainerType.NTAuth
                ? "NTAuth"
                : child.Properties["cn"][0].ToString();
            foreach (DsCertificateType type in certTypes) {
                List<DsCertificateEntry> items = readCertsFromDsAttribute(child, key, type);
                // add to global list
                foreach (DsCertificateEntry item in items) {
                    _list.Add(item);
                }
                // add to child-specific list.
                if (DsList.TryGetValue(key, out List<DsCertificateEntry> certEntryList)) {
                    certEntryList.AddRange(items);
                } else {
                    DsList.Add(key, items);
                }
            }
        }
    }
    /// <summary>
    /// Creates a list of entries within a container that should be updated upon write back to Active Directory.
    /// </summary>
    /// <returns>
    /// A collection of entry names that should be updated.
    /// </returns>
    protected IEnumerable<String> GetUpdateList() {
        ISet<String> namesToProcess = new HashSet<String>();
        // toBeAdded and toBeRemoved can overlap on different items only.
        foreach (String name in _toBeAdded) {
            namesToProcess.Add(name);
        }
        foreach (String name in _toBeRemoved) {
            namesToProcess.Add(name);
        }
        return namesToProcess;
    }
    /// <summary>
    /// Checks if the DS object can be deleted when it contains no certificates after certificate removal.
    /// This method does nothing if no certificates were removed from DS object. 
    /// </summary>
    /// <param name="entry">Specifies the DS entry to check.</param>
    /// <param name="entryName">Specifies the entry's CN name.</param>
    /// <returns>
    /// <strong>True</strong> if there are no more certificates and DS object is no longer necessary. Otherwise
    /// <strong>False</strong>.
    /// </returns>
    protected Boolean CheckDelete(DirectoryEntry entry, String entryName) {
        // if there was at least one removal and DS entry is empty from any certificate,
        // delete DS entry. Otherwise do nothing
        if (_toBeRemoved.Contains(entryName) && DsList[entryName].Count == 0) {
            BaseEntry.Children.Remove(entry);
            BaseEntry.CommitChanges();
            return true;
        }

        return false;
    }
    /// <summary>
    /// Adds new certificate entry to internal list.
    /// </summary>
    /// <param name="entry">Certificate entry to add.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>entry</strong> parameter is null.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if this is a new certificate and no duplicates exist. If certificate entry
    /// already exists in internal list, method returns <strong>False</strong>.
    /// </returns>
    protected Boolean AddCertificateEntry(DsCertificateEntry entry) {
        if (entry == null) {
            throw new ArgumentNullException(nameof(entry));
        }
        if (!_list.Add(entry)) { return false; }
        // mutually exclusive. entry cannot be added and removed at the same time.
        _toBeAdded.Add(entry.Name);
        _toBeRemoved.Remove(entry.Name);
        if (DsList.TryGetValue(entry.Name, out List<DsCertificateEntry> certEntryList)) {
            certEntryList.Add(entry);
        } else {
            DsList.Add(entry.Name, new List<DsCertificateEntry>());
            DsList[entry.Name].Add(entry);
        }

        return IsModified = true;
    }
    /// <summary>
    /// Removes certificate from internal list.
    /// </summary>
    /// <param name="entry">Certificate entry to remove.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>entry</strong> parameter is null.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if specified certificate entry was found, otherwise <strong>False</strong>.
    /// </returns>
    protected Boolean RemoveCertificateEntry(DsCertificateEntry entry) {
        if (entry == null) {
            throw new ArgumentNullException(nameof(entry));
        }
        if (!_list.Contains(entry)) {
            return false;
        }
        // mutually exclusive. entry cannot be added and removed at the same time.
        _toBeRemoved.Add(entry.Name);
        _toBeAdded.Remove(entry.Name);
        _list.Remove(entry);
        DsList[entry.Name].Remove(entry);

        return IsModified = true;
    }
    /// <summary>
    /// Gets sanitized DS object name from certificate's subject.
    /// </summary>
    /// <param name="fromCert">Specifies the certificate to use for DS name generation.</param>
    /// <returns>Sanitized name of DS object.</returns>
    /// <remarks>
    /// Default method implementation checks if specified certificate is CA certificate. If true, subject name
    /// is used to generate DS object name, otherwise issuer name is used to generate DS object name.
    /// </remarks>
    protected virtual String GetContainerName(X509Certificate2 fromCert) {
        X500DistinguishedName fullSubject;
        // get the name to be used as the name in DS. If certificate subject is end entity,
        // use issuer name (first attribute), if subject is CA, use subject name (first attribute).
        if (fromCert.Version == 3) {
            // attempt to retrieve Basic Constraints extension
            X509Extension ext = fromCert.Extensions[X509ExtensionOid.BasicConstraints];
            // if Basic Constraints is absent, pick issuer name
            if (ext == null) {
                fullSubject = fromCert.IssuerName;
            } else {
                // if Basic Constraints is presented, check if isCA attribute.
                // if isCA = TRUE, use subject name, otherwise use issuer name
                var bc = (X509BasicConstraintsExtension)ext.ConvertExtension();
                fullSubject = bc.CertificateAuthority
                    ? fromCert.SubjectName
                    : fromCert.IssuerName;
            }
        } else {
            // V1 certificates are treated as end entity, so pick up issuer name.
            fullSubject = fromCert.IssuerName;
        }

        return generateContainerName(fullSubject);
    }

    /// <summary>
    /// Performs internal collection cleanup after saving changes.
    /// </summary>
    protected void CleanupSave() {
        // clear processing lists
        _toBeAdded.Clear();
        _toBeRemoved.Clear();
        IsModified = false;
    }
}