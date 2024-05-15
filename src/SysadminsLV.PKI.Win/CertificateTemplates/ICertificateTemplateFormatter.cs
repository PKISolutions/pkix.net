#nullable enable
using System;
using System.Collections.Generic;
using PKI.CertificateTemplates;

namespace SysadminsLV.PKI.CertificateTemplates;

/// <summary>
/// Represents certificate template formatter contract information.
/// </summary>
public interface ICertificateTemplateFormatter {
    /// <summary>
    /// Exports certificate templates into a portable string.
    /// </summary>
    /// <param name="templates">A collection of templates to export.</param>
    /// <returns>
    ///     Serialized certificate templates in portable format. Return value must be compatible with <see cref="Deserialize"/>
    ///     method of same formatter.
    /// </returns>
    String Serialize(ICollection<CertificateTemplate> templates);
    /// <summary>
    /// Imports certificate templates from serialized templates string.
    /// </summary>
    /// <param name="serializedString">Serialized templates.</param>
    /// <returns>A collection of </returns>
    CertificateTemplateCollection Deserialize(String serializedString);
}