namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Specifies the logical operator of the data-query qualifier for the column. This parameter is used with the
/// <see cref="AdcsDbQueryFilter.QualifierValue"/> member to define the data-query qualifier.
/// </summary>
public enum AdcsDbSeekOperator {
    /// <summary>
    /// Equal to.
    /// </summary>
    EQ = 1,
    /// <summary>
    /// Less or equal to.
    /// </summary>
    LE = 2,
    /// <summary>
    /// Less than.
    /// </summary>
    LT = 4,
    /// <summary>
    /// Greater or equal to.
    /// </summary>
    GE = 8,
    /// <summary>
    /// Greater than.
    /// </summary>
    GT = 16
}