using System;

namespace SysadminsLV.PKI.Management.CertificateServices.Database {
    /// <summary>
    /// Represents an ADCS database query filter entry. Query filter consist of column name to use in the filter,
    /// logical operator of the data-query qualifier and query qualifier.
    /// </summary>
    /// <remarks>
    /// Query filters doesn't work on columns that store binary data.
    /// <para>When applying query filters on columns that store string data and logical operator is other than
    /// <strong>EQ</strong>, a binary string comparison is performed.
    /// is performed.</para>
    /// </remarks>
    public class AdcsDbQueryFilter {
        /// <summary>
        /// Initializes a new instance of <strong>AdcsDbQueryFilter</strong> class from column name,
        /// comparison operator and filter qualifier value.
        /// </summary>
        /// <param name="columnName">A valid column name to use in the filter.</param>
        /// <param name="op">A logical operator of the data-query qualifier.</param>
        /// <param name="value">A query qualifier value to use in the filter.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>columnName</strong> or <strong>value</strong> parameters is null.
        /// </exception>
        public AdcsDbQueryFilter(String columnName, AdcsDbSeekOperator op, Object value)
            : this(columnName, op, AdcsDbSortOrder.None, value) { }
        /// <summary>
        /// Initializes a new instance of <strong>AdcsDbQueryFilter</strong> class from column name,
        /// comparison operator, sorting order and filter qualifier value.
        /// </summary>
        /// <param name="columnName">A valid column name to use in the filter.</param>
        /// <param name="op">A logical operator of the data-query qualifier.</param>
        /// <param name="sort">Specifies the sort order for the column.</param>
        /// <param name="value">A query qualifier value to use in the filter.</param>
        /// <remarks>
        /// Indexed columns with zero or one filter can include a sort order of <strong>Ascending</strong>
        /// or <strong>Descending</strong>. Non-indexed columns or columns with two or more filters must use
        /// <strong>None</strong>.
        /// </remarks>
        public AdcsDbQueryFilter(String columnName, AdcsDbSeekOperator op, AdcsDbSortOrder sort, Object value) {
            if (String.IsNullOrEmpty(columnName)) {
                throw new ArgumentNullException(nameof(columnName));
            }

            ColumnName = columnName;
            LogicalOperator = op;
            SortOrder = sort;
            QualifierValue = value ?? throw new ArgumentNullException(nameof(value));
        }

        internal Int32 ColumnID { get; set; }
        /// <summary>
        /// A valid column name for the view or a predefined column specifier.
        /// </summary>
        public String ColumnName { get; }
        /// <summary>
        /// Specifies the logical operator of the data-query qualifier for the column. This parameter
        /// is used with the <see cref="QualifierValue"/> property to define the data-query qualifier.
        /// </summary>
        public AdcsDbSeekOperator LogicalOperator { get; }
        /// <summary>
        /// Specifies the sort order of the date-query qualifier for the column. Indexed columns with zero or one filter can include
        /// <strong>Ascending</strong> or <strong>Descending</strong>. Non-indexed columns or columns with two or more restrictions must
        /// use <strong>None</strong> for sorting.
        /// </summary>
        public AdcsDbSortOrder SortOrder { get; }
        /// <summary>
        /// Specifies the data query qualifier applied to this column. This parameter, along with the
        /// <see cref="LogicalOperator"/> parameter, determines which data is returned to the Certificate Services view.
        /// </summary>
        public Object QualifierValue { get; }

        /// <summary>
        /// Determines whether the specified object is equal to the current object. Two objects are equal when
        /// all public members in both objects are equals.
        /// </summary>
        /// <inheritdoc cref="Object.ToString" select="param|returns"/>
        public override Boolean Equals(Object obj) {
            return !(obj is null)
                   && (ReferenceEquals(this, obj)
                       || obj is AdcsDbQueryFilter other && Equals(other));
        }
        Boolean Equals(AdcsDbQueryFilter other) {
            return String.Equals(ColumnName, other.ColumnName, StringComparison.OrdinalIgnoreCase)
                   && LogicalOperator == other.LogicalOperator
                   && Equals(QualifierValue, other.QualifierValue);
        }
        /// <inheritdoc />
        public override Int32 GetHashCode() {
            unchecked {
                Int32 hashCode = ColumnName != null ? StringComparer.OrdinalIgnoreCase.GetHashCode(ColumnName) : 0;
                hashCode = (hashCode * 397) ^ (Int32) LogicalOperator;
                hashCode = (hashCode * 397) ^ (QualifierValue != null ? QualifierValue.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
