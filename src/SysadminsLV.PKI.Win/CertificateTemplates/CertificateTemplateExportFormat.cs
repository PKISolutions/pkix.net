#nullable enable
namespace SysadminsLV.PKI.CertificateTemplates;

/// <summary>
/// Represents supported built-in certificate template export/serialization formats.
/// </summary>
public enum CertificateTemplateExportFormat {
    /// <summary>
    /// Represents <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/08ec4475-32c2-457d-8c27-5a176660a210">[MS-XCEP]</see>
    /// compatible certificate template format.
    /// </summary>
    XCep = 0
}