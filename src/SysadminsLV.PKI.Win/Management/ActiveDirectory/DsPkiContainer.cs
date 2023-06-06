using System;
using System.Collections.Generic;
using System.DirectoryServices;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Management.ActiveDirectory;
/// <summary>
/// Represents a base class for PKI-related objects in Active Directory.
/// </summary>
public abstract class DsPkiContainer : IDisposable {
    String baseDsEntryPath;
    readonly String _pkiConfigContext;

    /// <summary>
    /// Initializes a new instance of <strong>DsPkiContainer</strong> class.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// The calling client is not a member of Active Directory domain or no domain controller can be contacted.
    /// </exception>
    protected DsPkiContainer() {
        if (!DsUtils.Ping()) {
            throw new PlatformNotSupportedException();
        }
        _pkiConfigContext = $",CN=Public Key Services,CN=Services,{DsUtils.ConfigContext}";
    }
    /// <summary>
    /// Gets an X.500 path to an Active Directory container.
    /// </summary>
    public String DsPath => $"{BaseEntryPath}{_pkiConfigContext}";
    /// <summary>
    /// Gets or sets container type in Active Directory.
    /// </summary>
    public DsContainerType ContainerType { get; protected set; }
    /// <summary>
    /// Indicates whether the container contents was changed.
    /// </summary>
    public Boolean IsModified { get; protected set; }
    /// <summary>
    /// Gets or sets a base path to this object in Active Directory.
    /// </summary>
    protected String BaseEntryPath {
        get => baseDsEntryPath;
        set {
            baseDsEntryPath = value;
            // do not throw exception if such object doesn't exist in Active Directory. It should be
            // created during SaveChanges method call.
            try {
                BaseEntry = new DirectoryEntry($"LDAP://{DsPath}");
            } catch { }

        }
    }
    /// <summary>
    /// Gets an instance of <see cref="DirectoryEntry"/> object associated with a current PKI container.
    /// </summary>
    protected DirectoryEntry BaseEntry { get; set; }
    /// <summary>
    /// Adds new entry under specified or current container.
    /// </summary>
    /// <param name="entry">Specifies the optional entry parent. If it is null, current DS object is used.</param>
    /// <param name="name">Specifies the name for new child.</param>
    /// <param name="dsObjectClass">Specifies the DS object class for new child.</param>
    /// <returns>Added child DS object.</returns>
    protected DirectoryEntry AddChild(DirectoryEntry entry, String name, String dsObjectClass) {
        DirectoryEntry parentEntry = entry ?? BaseEntry;
        entry = parentEntry.Children.Add(name, dsObjectClass);
        entry.Properties["cn"].Add(name.Replace("CN=", null));
        switch (dsObjectClass.ToLower()) {
            case "certificationauthority":
                fillCAMandatoryAttributes(entry);
                break;
            case "mspki-privatekeyrecoveryagent":
                fillKRAMandatoryAttributes(entry);
                break;
            case "crldistributionpoint":
                fillCRLMandatoryAttributes(entry);
                break;
        }
        entry.CommitChanges();
        entry.RefreshCache();
        return entry;
    }

    static void fillCAMandatoryAttributes(DirectoryEntry entry) {
        // fill mandatory properties: [MS-ADSC] §2.16 https://msdn.microsoft.com/en-us/library/cc221720.aspx
        entry.Properties["cACertificate"].Add(new Byte[] { 0 });
        entry.Properties["certificateRevocationList"].Add(new Byte[] { 0 });
        entry.Properties["authorityRevocationList"].Add(new Byte[] { 0 });
    }
    static void fillKRAMandatoryAttributes(DirectoryEntry entry) {
        // fill mandatory properties: [MS-ADSC] §2.170 https://msdn.microsoft.com/en-us/library/cc221673.aspx
        entry.Properties["userCertificate"].Add(new Byte[] { 0 });
    }
    static void fillCRLMandatoryAttributes(DirectoryEntry entry) {
        // fill mandatory properties: [MS-ADSC] §2.28 https://msdn.microsoft.com/en-us/library/cc221829.aspx
        entry.Properties["certificateRevocationList"].Add(new Byte[] { 0 });
    }


    /// <summary>
    /// Gets a property from an Active Directory object.
    /// </summary>
    /// <typeparam name="T">Specifies the expected output type.</typeparam>
    /// <param name="entry">
    /// A directory entry object. If this parameter is null, a <see cref="BaseEntry"/> object is used.
    /// </param>
    /// <param name="prop">Specifies the property name to query.</param>
    /// <returns>
    /// A collection of values of type speficies in the type parameter.
    /// </returns>
    /// <remarks>
    /// If actual property value doesn't match requested type (specified in the type parameter), the
    /// value is ignored and empty array is returned.
    /// </remarks>
    protected T[] GetEntryProperty<T>(DirectoryEntry entry, String prop) where T : class {
        DirectoryEntry localEntry = entry ?? BaseEntry;
        var list = new List<T>();
        if (localEntry.Properties.Contains(prop)) {
            foreach (Object propValue in localEntry.Properties[prop]) {
                if (!(propValue is T)) {
                    continue;
                }
                list.Add(propValue as T);
            }
        }
        return list.ToArray();
    }
    /// <summary>
    /// Adds a new container as a child of the specified object.
    /// </summary>
    /// <param name="parentPath">Path to an object where new child is added.</param>
    /// <param name="name">Child container common name.</param>
    /// <param name="schemaClassName">Child container DS schema class name.</param>
    /// <returns></returns>
    protected DirectoryEntry AddSubContainer(String parentPath, String name, String schemaClassName) {
        var entry = new DirectoryEntry(parentPath);
        return entry.Children.Add(name, schemaClassName);
    }

    /// <summary>
    /// Saves changes back to Active Directory.
    /// </summary>
    /// <param name="forceDelete">
    /// Forces object deletion if there are no more elements (certificates, CRLs, etc.).
    /// </param>
    /// <remarks>
    /// Typically, only members of Domain Admins group in forest root domain and members of Enterprise Admins
    /// group have permissions to write to Active Directory configuration naming context. Other members should
    /// be granted delegated permissions to write to configuration naming context.
    /// </remarks>
    public abstract void SaveChanges(Boolean forceDelete);

    /// <summary>
    /// Gets a specified Active Directory PKI container.
    /// </summary>
    /// <param name="containerType">AD PKI container to query.</param>
    /// <returns>
    /// AD PKI container.
    /// </returns>
    public static DsPkiContainer GetAdPkiContainer(DsContainerType containerType) {
        switch (containerType) {
            case DsContainerType.NTAuth:
                return new DsNTAuthContainer();
            case DsContainerType.AIA:
                return new DsAiaContainer();
            case DsContainerType.RootCA:
                return new DsRootCaContainer();
            case DsContainerType.CDP:
                return new DsCDPContainer();
            case DsContainerType.CertificateTemplates:
                return new DsCertTemplateContainer();
            case DsContainerType.KRA:
                return new DsKraContainer();
            case DsContainerType.EnrollmentServices:
                return new DsCertEnrollContainer();
            default:
                throw new ArgumentException("Specified container type is not supported");
        }
    }


    #region IDisposable
    void Dispose(Boolean disposing) {
        if (disposing) {
            BaseEntry?.Dispose();
        }
    }
    /// <inheritdoc />
    public void Dispose() {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    #endregion
}
