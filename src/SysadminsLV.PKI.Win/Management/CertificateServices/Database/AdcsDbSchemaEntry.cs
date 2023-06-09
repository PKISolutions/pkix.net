using System;

namespace SysadminsLV.PKI.Management.CertificateServices.Database {
    /// <summary>
    /// Represents Certification Authority database's table.
    /// </summary>
    public class AdcsDbSchemaEntry {

        internal AdcsDbSchemaEntry(String name, String displayname, AdcsDbColumnDataType datatype, Int32 maxlength, Boolean isindexed) {
            Name = name;
            DisplayName = displayname;
            DataType = datatype;
            MaxLength = maxlength;
            IsIndexed = isindexed;
        }

        /// <summary>
        /// Gets column's non-localized name.
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
        /// Indiciates whether the column is indexed.
        /// </summary>
        public Boolean IsIndexed { get; }
    }
}
