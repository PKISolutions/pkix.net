using PKI.CertificateTemplates;

namespace SysadminsLV.PKI.Dcom {
    public interface ICertPropWriterD {
        /// <summary>
        /// Writes certificate template list back to certification authority.
        /// </summary>
        /// <param name="templates">An array of certificate templates to set. Existing templates will be overwritten.</param>
        void SetTemplates(CertificateTemplate[] templates);
    }
}