using System;
using PKI.CertificateTemplates;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents a certificate template container in Active Directory.
    /// </summary>
    public class DsCertTemplateContainer : DsPkiContainer {

        internal DsCertTemplateContainer() {
            ContainerType = DsContainerType.CertificateTemplates;
            BaseEntryPath = "CN=Certificate Templates";
        }

        /// <summary>
        /// Gets an array of registered in Active Directory certificate templates.
        /// </summary>
        public CertificateTemplate[] CertificateTemplates => CertificateTemplate.EnumTemplates();

        /// <inheritdoc />
        public override void SaveChanges(Boolean forceDelete) { }
    }
}
