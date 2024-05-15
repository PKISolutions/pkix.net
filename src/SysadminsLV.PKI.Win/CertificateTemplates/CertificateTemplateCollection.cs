#nullable enable
using System;
using System.Collections.Generic;
using PKI.CertificateTemplates;

namespace SysadminsLV.PKI.CertificateTemplates;

/// <summary>
/// Represents a collection of AD CS Certificate Templates.
/// </summary>
public class CertificateTemplateCollection : BasicCollection<CertificateTemplate> {

    /// <summary>
    /// Initializes a new instance of <strong>Certificate Template</strong> class.
    /// </summary>
    public CertificateTemplateCollection() { }
    /// <summary>
    /// Initializes a new instance of <strong>Certificate Template</strong> class from existing collection.
    /// </summary>
    /// <param name="collection">Existing collection of certificate templates.</param>
    public CertificateTemplateCollection(IEnumerable<CertificateTemplate> collection) : base(collection) { }

    /// <summary>
    /// Exports current collection into a specified serialized format.
    /// </summary>
    /// <param name="format">Specifies the format to export current collection into.</param>
    /// <returns>Serialized string.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><strong>format</strong> value is not recognized.</exception>
    public String Export(CertificateTemplateExportFormat format) {
        return format switch {
            CertificateTemplateExportFormat.XCep => new CertificateTemplateXCepFormatter().Serialize(this),
            _                                    => throw new ArgumentOutOfRangeException(nameof(format), format, null)
        };
    }
    /// <summary>
    /// Exports current collection using specified formatter that implements <see cref="ICertificateTemplateFormatter"/> interface.
    /// </summary>
    /// <param name="formatter">Formatter.</param>
    /// <returns>Serialized string.</returns>
    public String Export(ICertificateTemplateFormatter formatter) {
        return formatter.Serialize(this);
    }

    /// <summary>
    /// Imports serialized certificate templates using specified serializer format into current list. If successful, imported templates
    /// will overwrite all templates in current collection.
    /// </summary>
    /// <param name="serializedString">Serialized string.</param>
    /// <param name="format">Serialized string format.</param>
    public void Import(String serializedString, CertificateTemplateExportFormat format) {
        CertificateTemplateCollection collection = format switch {
            CertificateTemplateExportFormat.XCep => new CertificateTemplateXCepFormatter().Deserialize(serializedString),
            _                                    => throw new ArgumentOutOfRangeException(nameof(format), format, null)
        };

        Clear();
        AddRange(collection);
    }
    /// <summary>
    /// Imports serialized certificate templates using specified formatter into current list. If successful, imported templates
    /// will overwrite all templates in current collection.
    /// </summary>
    /// <param name="serializedString">Serialized string.</param>
    /// <param name="formatter">Formatter.</param>
    public void Import(String serializedString, ICertificateTemplateFormatter formatter) {
        CertificateTemplateCollection collection = formatter.Deserialize(serializedString);

        Clear();
        AddRange(collection);
    }
}
