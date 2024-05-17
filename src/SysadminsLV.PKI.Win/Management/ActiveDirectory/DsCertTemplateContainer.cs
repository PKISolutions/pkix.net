using System;
using SysadminsLV.PKI.CertificateTemplates;

namespace SysadminsLV.PKI.Management.ActiveDirectory;
/// <summary>
/// Represents a certificate template container in Active Directory.
/// </summary>
public class DsCertTemplateContainer : DsPkiContainer {

    internal DsCertTemplateContainer() {
        ContainerType = DsContainerType.CertificateTemplates;
        BaseEntryPath = "CN=Certificate Templates";
        CertificateTemplates = CertificateTemplateFactory.GetTemplatesFromDs();
    }

    /// <summary>
    /// Gets an array of registered in Active Directory certificate templates.
    /// </summary>
    public CertificateTemplateCollection CertificateTemplates { get; }

    /// <inheritdoc />
    public override void SaveChanges(Boolean forceDelete) { }
}
