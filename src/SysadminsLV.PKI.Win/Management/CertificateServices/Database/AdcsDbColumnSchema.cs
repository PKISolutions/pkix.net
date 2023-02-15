using System;

namespace SysadminsLV.PKI.Management.CertificateServices.Database {
    /// <summary>
    /// Represents a description of ADCS database column schema.
    /// </summary>
    public class AdcsDbColumnSchema {
        /// <summary>
        /// Gets column language invariant name.
        /// </summary>
        public String Name { get; internal set; }
        /// <summary>
        /// Gets column localized name.
        /// </summary>
        public String DisplayName { get; internal set; }
        /// <summary>
        /// Gets data type for the data stored in the column.
        /// </summary>
        public AdcsDbColumnDataType DataType { get; internal set; }
        /// <summary>
        /// Gets maximum data capacity for the column in bytes.
        /// </summary>
        public Int32 MaxLength { get; internal set; }
        /// <summary>
        /// Indicates whether the column is indexed for faster column value search.
        /// </summary>
        public Boolean IsIndexed { get; internal set; }
    }
}
