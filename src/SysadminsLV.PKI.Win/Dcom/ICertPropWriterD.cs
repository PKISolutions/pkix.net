using PKI.CertificateTemplates;

namespace SysadminsLV.PKI.Dcom;
/// <summary>
/// Represents AD CS Certification Authority property writer interface.
/// </summary>
public interface ICertPropWriterD {
    /// <summary>
    /// Writes certificate template list back to certification authority.
    /// </summary>
    /// <param name="templates">An array of certificate templates to set. Existing templates will be overwritten.</param>
    void SetTemplates(CertificateTemplate[] templates);
}