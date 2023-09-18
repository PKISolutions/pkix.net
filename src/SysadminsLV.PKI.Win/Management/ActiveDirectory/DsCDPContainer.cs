using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Management.ActiveDirectory;

/// <summary>
/// Represents CRL Distribution Points (CDP) container in Active Directory.
/// </summary>
public class DsCDPContainer : DsPkiContainer {
    const String dsObjectClass = "cRLDistributionPoint";
    const String dsAttrBaseCrl = "certificateRevocationList";
    const String dsAttrDeltaCrl = "deltaRevocationList";
    readonly ISet<DsCrlEntry> _list = new HashSet<DsCrlEntry>();
    readonly ISet<DsCrlEntry> _toBeAdded   = new HashSet<DsCrlEntry>();
    readonly ISet<DsCrlEntry> _toBeRemoved = new HashSet<DsCrlEntry>();
    readonly IDictionary<String, List<DsCrlEntry>> _dsList = new Dictionary<String, List<DsCrlEntry>>(StringComparer.OrdinalIgnoreCase);

    internal DsCDPContainer() {
        ContainerType = DsContainerType.CDP;
        BaseEntryPath = "CN=CDP";
        readChildren();
    }

    /// <summary>
    /// Gets an array of CRL objects in Active Directory.
    /// </summary>
    public DsCrlEntry[] RevocationLists => _list.OrderBy(x => x.HostName).ThenBy(x => x.IssuerName).ToArray();

    void readChildren() {
        foreach (DirectoryEntry container in BaseEntry.Children) {
            String containerName = container.Properties["cn"][0].ToString();
            _dsList.Add(containerName, new List<DsCrlEntry>());
            foreach (DirectoryEntry entry in container.Children) {
                String entryName = entry.Properties["cn"][0].ToString();
                if (entry.SchemaClassName != dsObjectClass) { continue; }
                X509CRL2 baseCrl = readBaseCRL(entry);
                if (baseCrl != null) {
                    addCrlEntryFromDS(containerName, entryName, baseCrl);
                }
                X509CRL2 deltaCrl = readDeltaCrl(entry);
                if (deltaCrl != null) {
                    addCrlEntryFromDS(containerName, entryName, deltaCrl);
                }
                entry.Dispose();
            }
            container.Dispose();
        }
    }
    void addCrlEntryFromDS(String containerName, String entryName, X509CRL2 crl) {
        var crlEntry = new DsCrlEntry(containerName, entryName, crl);
        _list.Add(crlEntry);
        _dsList[containerName].Add(crlEntry);
    }
    static X509CRL2 readBaseCRL(DirectoryEntry entry) {
        Byte[] baseCrlBytes = (Byte[])entry.Properties[dsAttrBaseCrl].Value;
        if (baseCrlBytes != null && baseCrlBytes.Length <= 1) {
            return null;
        }
        try {
            return new X509CRL2(baseCrlBytes);
        } catch {
            return null;
        }
    }
    static X509CRL2 readDeltaCrl(DirectoryEntry entry) {
        PropertyValueCollection deltaCrls = entry.Properties[dsAttrDeltaCrl];
        if (deltaCrls.Count < 1 || ((Byte[])deltaCrls[0]).Length <= 1) {
            return null;
        }
        try {
            return new X509CRL2((Byte[])deltaCrls[0]);
        } catch {
            return null;
        }
    }
    static String getHostName(String suggestedHostName, X509CRL2 crl) {
        if (String.IsNullOrWhiteSpace(suggestedHostName)) {
            var pubCrl = (X509PublishedCrlLocationsExtension)crl.Extensions[X509ExtensionOid.PublishedCrlLocations];
            if (pubCrl == null) {
                throw new ArgumentException("Cannot find target location.");
            }
            String[] urls = pubCrl.GetUrLs().Where(x => x.ToUpper().Contains("LDAP://")).ToArray();
            if (urls.Length == 0) {
                throw new ArgumentException("Cannot find target location.");
            }
            String[] tokens = urls[0].ToUpper().Split(new[] { "CN=" }, StringSplitOptions.RemoveEmptyEntries);
            suggestedHostName = tokens[2];
        }
        return suggestedHostName;
    }
    static String getEntryName(X509CRL2 crl) {
        var pubCrl = (X509PublishedCrlLocationsExtension)crl.Extensions[X509ExtensionOid.PublishedCrlLocations];
        return pubCrl == null
            ? getEntryNameFromIssuer(crl)
            : getEntryNameFromUrl(pubCrl);
    }
    static String getEntryNameFromUrl(X509PublishedCrlLocationsExtension pubCrl) {
        String[] urls = pubCrl.GetUrLs().Where(x => x.ToUpper().Contains("LDAP://")).ToArray();
        if (urls.Length == 0) {
            throw new ArgumentException("Cannot find target location.");
        }
        String[] tokens = urls[0].Split(new[] { "CN=" }, StringSplitOptions.RemoveEmptyEntries);
        return HttpUtility.UrlDecode(tokens[1].TrimEnd(','));
    }
    static String getEntryNameFromIssuer(X509CRL2 crl) {
        X500RdnAttributeCollection tokens = crl.IssuerName.GetRdnAttributes();
        String objectName;
        // if subject is empty, calculate SHA1 hash over subject name's raw data (48, 0)
        if (tokens.Count == 0) {
            var sb = new StringBuilder();
            using (var hasher = SHA1.Create()) {
                foreach (Byte b in hasher.ComputeHash(crl.IssuerName.RawData)) {
                    sb.AppendFormat("{0:x2}", b);
                }
            }
            objectName = sb.ToString();
        }
        else {
            objectName = tokens[0].Value;
        }
        var caVersion = (X509CAVersionExtension) crl.Extensions[X509ExtensionOid.CAVersion];
        if (caVersion == null || caVersion.CAKeyVersion < 1) {
            return objectName;
        }
        return DsUtils.GetSanitizedName($"{objectName}({caVersion.CAKeyVersion})");
    }
    IDictionary<String, ISet<String>> getUpdateList() {
        var retValue = new Dictionary<String, ISet<String>>();
        foreach (DsCrlEntry name in _toBeAdded) {
            if (!retValue.ContainsKey(name.HostName)) {
                retValue.Add(name.HostName, new HashSet<String>());
            }
            retValue[name.HostName].Add(name.IssuerName);
        }
        foreach (DsCrlEntry name in _toBeRemoved) {
            if (!retValue.ContainsKey(name.HostName)) {
                retValue.Add(name.HostName, new HashSet<String>());
            }
            retValue[name.HostName].Add(name.IssuerName);
        }
        return retValue;
    }
    DirectoryEntry getTopContainer(String name) {
        try {
            return BaseEntry.Children.Find($"CN={name}");
        } catch {
            DirectoryEntry entry = BaseEntry.Children.Add($"CN={name}", "container");
            entry.CommitChanges();
            entry.RefreshCache();
            return entry;
        }
    }
    Boolean checkDelete(DirectoryEntry topContainer, DirectoryEntry entry) {
        String topName = topContainer.Properties["cn"].Value.ToString();
        String entryName = entry.Properties["cn"].Value.ToString();
        // if there was at least one removal and DS entry is empty from any CRL,
        // delete DS entry. Otherwise do nothing
        if (_toBeRemoved.Any(x => x.HostName.Equals(topName, StringComparison.OrdinalIgnoreCase)
                                  && x.IssuerName.Equals(entryName, StringComparison.OrdinalIgnoreCase))
            && !_dsList[topName].Any(x => x.IssuerName.Equals(entryName, StringComparison.OrdinalIgnoreCase))) {
            topContainer.Children.Remove(entry);
            topContainer.CommitChanges();
            return true;
        }
        return false;
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

    /// <summary>
    /// Adds new certificate revocation list to Active Directory.
    /// </summary>
    /// <param name="crl">Specifies a CRL to publish in Active Directory.</param>
    /// <param name="hostName">
    /// Specifies host name of CA server that issued the CRL. This parameter is optional and can be omitted if
    /// CRL includes <strong>Published CRL Locations</strong> CRL extension. If specified, this parameter takes
    /// precedence over <strong>Published CRL Locations</strong> extension value.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <strong>crl</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// There is no enough information to determine exact CRL publication location in Active Directory.
    /// </exception>
    /// <returns>
    /// This method always returns <strong>True</strong>.
    /// </returns>
    public Boolean AddCrl(X509CRL2 crl, String hostName = null) {
        if (crl == null) {
            throw new ArgumentNullException(nameof(crl));
        }
        String issuerName = getEntryName(crl);
        hostName = getHostName(hostName, crl);
        var entry = new DsCrlEntry(hostName, issuerName, crl);
        // we do not store multiple CRLs for single entry, instead, we overwrite them.
        // therefore we remove old entry and add new one (replace).
        _list.Remove(entry);
        _list.Add(entry);
        _toBeAdded.Add(entry);
        if (!_dsList.ContainsKey(hostName)) {
            _dsList.Add(hostName, new List<DsCrlEntry>());
        }
        _dsList[hostName].Remove(entry);
        _dsList[hostName].Add(entry);
        return IsModified = true;
    }
    /// <summary>
    /// Removes CRL entry from Active Directory.
    /// </summary>
    /// <param name="entry">CRL entry to remove.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>entry</strong> parameter is null.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if specified CRL entry was found, otherwise <strong>False</strong>.
    /// </returns>
    public Boolean RemoveCrl(DsCrlEntry entry) {
        if (entry == null) {
            throw new ArgumentNullException(nameof(entry));
        }
        if (!_list.Remove(entry)) {
            return false;
        }
        // mutually exclusive. entry cannot be added and removed at the same time.
        _toBeRemoved.Add(entry);
        _toBeAdded.Remove(entry);
        _dsList[entry.HostName].Remove(entry);
        return IsModified = true;
    }


    /// <inheritdoc />
    public override void SaveChanges(Boolean forceDelete) {
        if (!IsModified) { return; }
        // this list contains only entries we need to update.
        IDictionary<String, ISet<String>> updateList = getUpdateList();
        foreach (String topName in updateList.Keys) {
            using DirectoryEntry topContainer = getTopContainer(topName);
            foreach (String name in updateList[topName]) {
                Console.WriteLine($"LDAP://CN={name},CN={topName},{DsPath}");
                DirectoryEntry dsEntry = DirectoryEntry.Exists($"LDAP://CN={name},CN={topName},{DsPath}")
                    ? new DirectoryEntry($"LDAP://CN={name},CN={topName},{DsPath}")
                    // if no such entry exists, create it.
                    : AddChild(topContainer, $"CN={name}", dsObjectClass);
                // if we elected to delete empty entries --> check them
                if (forceDelete && checkDelete(topContainer, dsEntry)) {
                    continue;
                }
                // write Base CRLs
                dsEntry.Properties[dsAttrBaseCrl].Clear();
                DsCrlEntry[] baseCrls = _dsList[topName].Where(x => x.IssuerName.Equals(name, StringComparison.OrdinalIgnoreCase) && x.CrlType == X509CrlType.BaseCrl).ToArray();
                // base CRL attribute is mandatory attribute
                if (!baseCrls.Any()) {
                    dsEntry.Properties[dsAttrBaseCrl].Add(new Byte[] { 0 });
                } else {
                    foreach (DsCrlEntry entry in baseCrls) {
                        dsEntry.Properties[dsAttrBaseCrl].Add(entry.CRL.RawData);
                    }
                }
                // write delta CRLs
                dsEntry.Properties[dsAttrDeltaCrl].Clear();
                foreach (DsCrlEntry entry in _dsList[topName].Where(x => x.IssuerName.Equals(name, StringComparison.OrdinalIgnoreCase) && x.CrlType == X509CrlType.DeltaCrl)) {
                    dsEntry.Properties[dsAttrDeltaCrl].Add(entry.CRL.RawData);
                }
                dsEntry.CommitChanges();
                dsEntry.Dispose();
            }
            topContainer.Dispose();
        }
        CleanupSave();
    }
}