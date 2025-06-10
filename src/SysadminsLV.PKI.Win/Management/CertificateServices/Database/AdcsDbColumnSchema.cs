using System;
using CERTADMINLib;

namespace SysadminsLV.PKI.Management.CertificateServices.Database; 
/// <summary>
/// Represents a description of ADCS database column schema.
/// </summary>
public class AdcsDbColumnSchema {
    internal AdcsDbColumnSchema(IEnumCERTVIEWCOLUMN certViewColumn) {
        Name = certViewColumn.GetName();
        DisplayName = certViewColumn.GetDisplayName();
        DataType = (AdcsDbColumnDataType)certViewColumn.GetType();
        MaxLength = certViewColumn.GetMaxLength();
        IsIndexed = Convert.ToBoolean(certViewColumn.IsIndexed());
    }
    
    /// <summary>
    /// Gets column language invariant name.
    /// </summary>
    public String Name { get; }
    /// <summary>
    /// Gets column localized name.
    /// </summary>
    public String DisplayName { get; }
    /// <summary>
    /// Gets data type for the data stored in the column.
    /// </summary>
    public AdcsDbColumnDataType DataType { get; }
    /// <summary>
    /// Gets maximum data capacity for the column in bytes.
    /// </summary>
    public Int32 MaxLength { get; }
    /// <summary>
    /// Indicates whether the column is indexed for faster column value search.
    /// </summary>
    public Boolean IsIndexed { get; }
}
