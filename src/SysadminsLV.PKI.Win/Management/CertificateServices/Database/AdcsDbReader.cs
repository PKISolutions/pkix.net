using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CERTADMINLib;
using PKI.CertificateServices;
using PKI.CertificateTemplates;
using PKI.Structs;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Dcom.Implementations;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Management.CertificateServices.Database;

/// <summary>
/// Represents Active Directory Certificate Services (ADCS) managed database reader engine.
/// </summary>
public class AdcsDbReader : IDisposable {
    #region predefined columns per view table
    static readonly String[] _revokedColumns = [
        AdcsDbColumnName.Request_ID,
        AdcsDbColumnName.Request_Revoked_When,
        AdcsDbColumnName.Request_Revoked_Reason,
        AdcsDbColumnName.Common_Name,
        AdcsDbColumnName.Serial_Number,
        AdcsDbColumnName.Certificate_Template
    ];
    static readonly String[] _issuedColumns = [
        AdcsDbColumnName.Request_ID,
        AdcsDbColumnName.Request_Requester_Name,
        AdcsDbColumnName.Common_Name,
        AdcsDbColumnName.Not_Before,
        AdcsDbColumnName.Not_After,
        AdcsDbColumnName.Serial_Number,
        AdcsDbColumnName.Certificate_Template
    ];
    static readonly String[] _pendingColumns = [
        AdcsDbColumnName.Request_ID,
        AdcsDbColumnName.Request_Requester_Name,
        AdcsDbColumnName.Request_Submitted_When,
        AdcsDbColumnName.Request_Common_Name,
        AdcsDbColumnName.Certificate_Template
    ];
    static readonly String[] _failedColumns = [
        AdcsDbColumnName.Request_ID,
        AdcsDbColumnName.Request_Status_Code,
        AdcsDbColumnName.Request_Disposition_Message,
        AdcsDbColumnName.Request_Requester_Name,
        AdcsDbColumnName.Request_Submitted_When,
        AdcsDbColumnName.Request_Common_Name,
        AdcsDbColumnName.Certificate_Template
    ];
    static readonly String[] _requestColumns = [
        AdcsDbColumnName.Request_ID,
        AdcsDbColumnName.Request_Status_Code,
        AdcsDbColumnName.Request_Disposition_Message,
        AdcsDbColumnName.Request_Requester_Name,
        AdcsDbColumnName.Request_Submitted_When,
        AdcsDbColumnName.Request_Common_Name,
        AdcsDbColumnName.Certificate_Template
    ];
    static readonly String[] _extensionColumns = [
        AdcsDbColumnName.Extension_Request_ID,
        AdcsDbColumnName.Extension_Name,
        AdcsDbColumnName.Extension_Flags,
        AdcsDbColumnName.Extension_Raw_Value
    ];
    static readonly String[] _attributeColumns = [
        AdcsDbColumnName.Attribute_Request_ID,
        AdcsDbColumnName.Attribute_Name,
        AdcsDbColumnName.Attribute_Value
    ];
    static readonly String[] _crlColumns = [
        AdcsDbColumnName.CRL_Row_ID,
        AdcsDbColumnName.CRL_Number,
        AdcsDbColumnName.CRL_This_Update,
        AdcsDbColumnName.CRL_Next_Update,
        AdcsDbColumnName.CRL_Publish_Status_Code,
        AdcsDbColumnName.CRL_Publish_Error
    ];
    #endregion
    readonly ICertView2 _caView = CertAdminFactory.CreateICertView();
    IEnumCERTVIEWROW dbRow;
    readonly ISet<Int32> _columnIDs = new HashSet<Int32>();
    readonly IList<String> _columns = new List<String>();
    readonly ISet<AdcsDbQueryFilter> _filters = new HashSet<AdcsDbQueryFilter>();
    AdcsDbTableName table;
    Boolean isOpenView, outAllColumns, allSet;

    /// <summary>
    /// Initializes a new instance of <strong>AdcsDbReader</strong> from a certification authority object
    /// and table to read.
    /// </summary>
    /// <param name="certificateAuthority">Certification Authority object to connect to.</param>
    /// <param name="viewTable">Table name to view. Default view table is set to <strong>Issued</strong>.</param>
    /// <remarks>
    /// This class implements <see cref="IDisposable"/> interface and it is advised to put the object into
    /// <code>using</code> (C#) or <code>Using</code> (Visual Basic) statement block or explicitly call
    /// <see cref="Dispose"/> method when current object is no longer needed to release all unmanaged resources.
    /// </remarks>
    internal AdcsDbReader(CertificateAuthority certificateAuthority, AdcsDbViewTableName viewTable = AdcsDbViewTableName.Issued) {
        ConfigString = certificateAuthority.ConfigString;
        _caView.OpenConnection(ConfigString);
        ViewTable = viewTable;
        mapTables();
    }

    /// <summary>
    /// Gets the CA's config string associated with the current database reader instance.
    /// </summary>
    public String ConfigString { get; }
    /// <summary>
    /// Gets an array of database columns added to include in the view.
    /// </summary>
    public String[] Columns => _columns.ToArray();
    /// <summary>
    /// Gets an array of currently applied query filters.
    /// </summary>
    public AdcsDbQueryFilter[] QueryFilters => _filters.ToArray();
    /// <summary>
    /// Gets the view table to query. Default is '<strong>Request</strong>' view table.
    /// </summary>
    /// <remarks>
    /// Depending on view table, predefined column list is added to a result view.
    /// <list type="table">
    ///     <listheader>
    ///         <term>View Table</term>
    ///         <description>Default columns</description>
    ///     </listheader>
    ///     <item>
    ///          <term>Revoked</term>
    ///          <description>
    ///             <list type="bullet">
    ///                 <item>RequestID</item>
    ///                 <item>Request.RevokedWhen</item>
    ///                 <item>Request.RevokedReason</item>
    ///                 <item>CommonName</item>
    ///                 <item>SerialNumber</item>
    ///                 <item>CertificateTemplate</item>
    ///             </list>
    ///         </description>
    ///     </item>
    ///     <item>
    ///          <term>Issued</term>
    ///          <description>
    ///             <list type="bullet">
    ///                 <item>RequestID</item>
    ///                 <item>Request.RequesterName</item>
    ///                 <item>CommonName</item>
    ///                 <item>NotBefore</item>
    ///                 <item>NotAfter</item>
    ///                 <item>SerialNumber</item>
    ///                 <item>CertificateTemplate</item>
    ///             </list>
    ///         </description>
    ///     </item>
    ///     <item>
    ///          <term>Pending</term>
    ///          <description>
    ///             <list type="bullet">
    ///                 <item>RequestID</item>
    ///                 <item>Request.RequesterName</item>
    ///                 <item>Request.SubmittedWhen</item>
    ///                 <item>CommonName</item>
    ///                 <item>CertificateTemplate</item>
    ///             </list>
    ///         </description>
    ///     </item>
    ///     <item>
    ///          <term>Failed</term>
    ///          <description>
    ///             <list type="bullet">
    ///                 <item>RequestID</item>
    ///                 <item>Request.StatusCode</item>
    ///                 <item>Request.DispositionMessage</item>
    ///                 <item>Request.SubmittedWhen</item>
    ///                 <item>Request.CommonName</item>
    ///                 <item>CertificateTemplate</item>
    ///             </list>
    ///         </description>
    ///     </item>
    ///     <item>
    ///          <term>Request</term>
    ///          <description>
    ///             <list type="bullet">
    ///                 <item>RequestID</item>
    ///                 <item>Request.StatusCode</item>
    ///                 <item>Request.DispositionMessage</item>
    ///                 <item>Request.RequesterName</item>
    ///                 <item>Request.SubmittedWhen</item>
    ///                 <item>Request.CommonName</item>
    ///                 <item>CertificateTemplate</item>
    ///             </list>
    ///         </description>
    ///     </item>
    ///     <item>
    ///          <term>Extension</term>
    ///          <description>
    ///             <list type="bullet">
    ///                 <item>ExtensionRequestId</item>
    ///                 <item>ExtensionName</item>
    ///                 <item>ExtensionFlags</item>
    ///                 <item>ExtensionRawValue</item>
    ///             </list>
    ///         </description>
    ///     </item>
    ///     <item>
    ///          <term>Attribute</term>
    ///          <description>
    ///             <list type="bullet">
    ///                 <item>AttributeRequestId</item>
    ///                 <item>AttributeName</item>
    ///                 <item>AttributeValue</item>
    ///             </list>
    ///         </description>
    ///     </item>
    ///     <item>
    ///          <term>CRL</term>
    ///          <description>
    ///             <list type="bullet">
    ///                 <item>CRLRowId</item>
    ///                 <item>CRLNumber</item>
    ///                 <item>CRLThisUpdate</item>
    ///                 <item>CRLNextUpdate</item>
    ///                 <item>CRLPublishStatusCode</item>
    ///                 <item>CRLPublishError</item>
    ///             </list>
    ///         </description>
    ///     </item>
    /// </list>
    /// </remarks>
    public AdcsDbViewTableName ViewTable { get; }

    void mapTables() {
        Int32 RColumn = _caView.GetColumnIndex(0, AdcsDbColumnName.Request_Disposition);
        // map view table to DB table
        String[] columns;
        switch (ViewTable) {
            case AdcsDbViewTableName.Revoked:
                columns = _revokedColumns;
                table = AdcsDbTableName.Request;
                _caView.SetRestriction(RColumn, 1, 0, 21);
                break;
            case AdcsDbViewTableName.Issued:
                columns = _issuedColumns;
                table = AdcsDbTableName.Request;
                _caView.SetRestriction(RColumn, 1, 0, 20);
                break;
            case AdcsDbViewTableName.Pending:
                columns = _pendingColumns;
                table = AdcsDbTableName.Request;
                _caView.SetRestriction(RColumn, 1, 0, 9);
                break;
            case AdcsDbViewTableName.Failed:
                columns = _failedColumns;
                table = AdcsDbTableName.Request;
                _caView.SetRestriction(-3, 0, 0, 0);
                break;
            case AdcsDbViewTableName.Request:
                columns = _requestColumns;
                table = AdcsDbTableName.Request;
                _caView.SetTable((Int32)AdcsDbTableName.Request);
                break;
            case AdcsDbViewTableName.Extension:
                columns = _extensionColumns;
                table = AdcsDbTableName.Extension;
                _caView.SetTable((Int32)AdcsDbTableName.Extension);
                break;
            case AdcsDbViewTableName.Attribute:
                columns = _attributeColumns;
                table = AdcsDbTableName.Attribute;
                _caView.SetTable((Int32)AdcsDbTableName.Attribute);
                break;
            case AdcsDbViewTableName.CRL:
                columns = _crlColumns;
                table = AdcsDbTableName.CRL;
                _caView.SetTable((Int32)AdcsDbTableName.CRL);
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }
        // set columns for preconfigured view tables
        foreach (String column in columns) {
            AddColumnToView(column);
        }
    }
    void setResultColumns() {
        Int32 columnCount;
        if (outAllColumns) {
            columnCount = _caView.GetColumnCount(CertAdmConstants.CVRC_COLUMN_SCHEMA);
            _caView.SetResultColumnCount(columnCount);
            _columns.Clear();
            _columns.Add("*");
            foreach (Int32 columnIndex in Enumerable.Range(0, columnCount)) {
                _caView.SetResultColumn(columnIndex);
            }
        } else {
            columnCount = _columnIDs.Count;
            _caView.SetResultColumnCount(columnCount);
            foreach (Int32 columnID in _columnIDs) {
                _caView.SetResultColumn(columnID);
            }
        }
    }
    void setFilters() {
        foreach (AdcsDbQueryFilter filter in _filters) {
            _caView.SetRestriction(
                filter.ColumnID,
                (Int32)filter.LogicalOperator,
                (Int32)filter.SortOrder,
                filter.QualifierValue);
        }
    }

    IEnumerable<AdcsDbRow> enumRows(Int32 skipRows, Int32 takeRows) {
        Int32 rowsTaken = 0;
        dbRow.Skip(skipRows);
        while (dbRow.Next() != -1 && rowsTaken < takeRows) {
            rowsTaken++;
            var row = new AdcsDbRow {
                ConfigString = ConfigString,
                Table = table
            };
            enumColumnView(dbRow, row);
            postProcessRow(row);
            yield return row;
        }
        dbRow.Reset();
    }
    static void enumColumnView(IEnumCERTVIEWROW dbRow, AdcsDbRow row) {
        IEnumCERTVIEWCOLUMN dbColumn = dbRow.EnumCertViewColumn();
        while (dbColumn.Next() != -1) {
            String colName = dbColumn.GetName();
            Object colVal = dbColumn.GetValue(CertAdmConstants.CV_OUT_BASE64);
            switch (colName) {
                case AdcsDbColumnName.Request_ID:
                case AdcsDbColumnName.Extension_Request_ID:
                case AdcsDbColumnName.Attribute_Request_ID:
                case AdcsDbColumnName.CRL_Row_ID:
                    row.RowId = (Int32)colVal;
                    break;
            }
            row.Properties.Add(colName, colVal);
        }
        CryptographyUtils.ReleaseCom(dbColumn);
    }
    static void postProcessRow(AdcsDbRow row) {
        setPropertyFlags<AdcsDbRequestType>(row, AdcsDbColumnName.Request_Request_Type);
        setPropertyFlags<AdcsDbRequestFlags>(row, AdcsDbColumnName.Request_Request_Flags);
        setPropertyFlags<CertificateTemplateEnrollmentFlags>(row, AdcsDbColumnName.Enrollment_Flags);
        setPropertyFlags<CertificateTemplateFlags>(row, AdcsDbColumnName.General_Flags);
        setPropertyFlags<PrivateKeyFlags>(row, AdcsDbColumnName.PrivateKey_Flags);
        setPropertyFlags<AdcsDbExtensionFlags>(row, AdcsDbColumnName.Extension_Flags);
        setPropertyFlags<AdcsDbCrlPublishFlags>(row, AdcsDbColumnName.CRL_Publish_Flags);
        
        if (row.Properties.TryGetValue(AdcsDbColumnName.Certificate_Template, out Object templateName) && !String.IsNullOrWhiteSpace((String)templateName)) {
            row.Properties[AdcsDbColumnName.Certificate_Template + "Oid"] = new Oid((String)templateName);
        }
        if (row.Table == AdcsDbTableName.Extension) {
            if (row.Properties.TryGetValue(AdcsDbColumnName.Extension_Name, out Object name)) {
                // add extension name as OID.
                row.Properties.Add(AdcsDbColumnName.Extension_Name + "Oid", new Oid((String)name));
                if (row.Properties.TryGetValue(AdcsDbColumnName.Extension_Flags, out Object rawFlags) && row.Properties.TryGetValue(AdcsDbColumnName.Extension_Raw_Value, out Object value)) {
                    // add X509Extension object to the row.
                    AdcsDbExtensionFlags flags = (AdcsDbExtensionFlags)rawFlags;
                    Boolean critical = (flags & AdcsDbExtensionFlags.Critical) != 0;
                    var baseExtension = new X509Extension((String)name, Convert.FromBase64String((String)value), critical);
                    try {
                        row.Properties["ExtensionObject"] = baseExtension.ConvertExtension();
                    } catch {
                        row.Properties["ExtensionObject"] = baseExtension;
                    }
                }
            }
        }
    }
    
    static void setPropertyFlags<TEnum>(AdcsDbRow row, String columnName) where TEnum : Enum {
        const String propSuffix = "Enum";
        if (row.Properties.TryGetValue(columnName, out Object columnValue)) {
            row.Properties.Add(columnName + propSuffix, (TEnum)columnValue);
        }
    }

    /// <summary>
    /// Adds database table column to output.
    /// </summary>
    /// <param name="columnName">Column name to include.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>columnName</strong> parameter is null or empty string.
    /// </exception>
    ///  <exception cref="AccessViolationException">
    /// Database view is already opened and cannot be altered.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if column is added to the view. <strong>False</strong> if column is already added
    /// or column name is not valid.
    /// </returns>
    /// <remarks>
    /// Valid column names can be retrieved by running <see cref="GetTableSchema"/> method. Use '*' (asterisk)
    /// in order to add all columns to the output view.
    /// <para>Use <see cref="GetDefaultColumns"/> method to retrieve default columns added to the view.</para>
    /// </remarks>
    public Boolean AddColumnToView(String columnName) {
        if (isOpenView) {
            throw new AccessViolationException();
        }
        if (String.IsNullOrWhiteSpace(columnName)) {
            throw new ArgumentNullException(nameof(columnName));
        }

        // if '*' is specified then all columns are added implicitly, so return false.
        if (outAllColumns) { return false; }
        if (columnName == "*") {
            outAllColumns = true;
            return true;
        }
        Int32 index;
        try {
            index = _caView.GetColumnIndex(0, columnName);
        } catch {
            return false;
        }
        if (_columnIDs.Add(index)) {
            _columns.Add(columnName);
            return true;
        }
        return false;
    }
    /// <summary>
    /// Adds query filter to requested view.
    /// </summary>
    /// <param name="filter">Filter entry to add.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>filter</strong> parameter is null.
    /// </exception>
    /// <exception cref="AccessViolationException">
    /// Database view is already opened and cannot be altered.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if filter is added, if filter is already added or the filter column is not valid
    /// the method returns <strong>False</strong>.
    /// </returns>
    public Boolean AddQueryFilter(AdcsDbQueryFilter filter) {
        if (filter == null) { throw new ArgumentNullException(nameof(filter)); }
        if (isOpenView) {
            throw new AccessViolationException();
        }
        if (_filters.Contains(filter)) { return false; }
        Int32 index;
        try {
            index = _caView.GetColumnIndex(0, filter.ColumnName);
        } catch {
            return false;
        }
        filter.ColumnID = index;
        return _filters.Add(filter);
    }
    /// <summary>
    /// Gets a database row view based on a current configuration. 
    /// </summary>
    /// <param name="skipRows">Number of rows to skip. Default is 0.</param>
    /// <param name="takeRows">Number of rows to fetch. Default is unlimited.</param>
    /// <returns>Database row view enumerator.</returns>
    /// <remarks>
    /// After calling this method, CA database reader configuration cannot be altered. That is, no columns
    /// or query filters can be added. In order to change reader configuration, a new instance of
    /// <strong>AdcsDbReader</strong> class must be created.
    /// <para>This method supports <code>yield return</code> statement and returns row as quickly as
    /// they are retrieved by a reader.</para>
    /// </remarks>
    public IEnumerable<AdcsDbRow> GetView(Int32 skipRows = 0, Int32 takeRows = Int32.MaxValue) {
        isOpenView = true;
        if (!allSet) {
            setResultColumns();
            setFilters();
            allSet = true;
        }
        if (dbRow == null) {
            dbRow = _caView.OpenView();
        } else {
            dbRow.Reset();
        }
        foreach (AdcsDbRow row in enumRows(skipRows, takeRows)) {
            yield return row;
        }
    }
    /// <summary>
    /// Gets ADCS database schema for specified table. Table name is specified in <see cref="ViewTable"/> property.
    /// </summary>
    /// <returns>An array of table columns and their schema details.</returns>
    public AdcsDbColumnSchema[] GetTableSchema() {
        CCertView schemaView = new CCertView();
        List<AdcsDbColumnSchema> items = [];
        schemaView.OpenConnection(ConfigString);
        schemaView.SetTable((Int32)table);
        IEnumCERTVIEWCOLUMN columns = schemaView.EnumCertViewColumn(0);
        while (columns.Next() != -1) {
            var column = new AdcsDbColumnSchema {
                Name = columns.GetName(),
                DisplayName = columns.GetDisplayName(),
                DataType = (AdcsDbColumnDataType)columns.GetType(),
                MaxLength = columns.GetMaxLength(),
                IsIndexed = Convert.ToBoolean(columns.IsIndexed())
            };
            items.Add(column);
        }
        CryptographyUtils.ReleaseCom(columns, schemaView);
        return items.ToArray();
    }

    /// <summary>
    /// Gets a list of default columns added to the view based on a view table.
    /// </summary>
    /// <param name="table">View table to fetch.</param>
    /// <returns>An array of column names.</returns>
    public static String[] GetDefaultColumns(AdcsDbViewTableName table) {
        switch (table) {
            case AdcsDbViewTableName.Attribute:
                return _attributeColumns;
            case AdcsDbViewTableName.CRL:
                return _crlColumns;
            case AdcsDbViewTableName.Extension:
                return _extensionColumns;
            case AdcsDbViewTableName.Failed:
                return _failedColumns;
            case AdcsDbViewTableName.Issued:
                return _issuedColumns;
            case AdcsDbViewTableName.Pending:
                return _pendingColumns;
            case AdcsDbViewTableName.Revoked:
                return _revokedColumns;
            case AdcsDbViewTableName.Request:
                return _requestColumns;
            default:
                throw new ArgumentOutOfRangeException(nameof(table));
        }
    }

    #region IDisposable
    void releaseUnmanagedResources() {
        if (dbRow != null) {
            CryptographyUtils.ReleaseCom(dbRow);
        }
        CryptographyUtils.ReleaseCom(_caView);
    }
    /// <inheritdoc />
    public void Dispose() {
        releaseUnmanagedResources();
        GC.SuppressFinalize(this);
    }
    /// <inheritdoc />
    ~AdcsDbReader() {
        releaseUnmanagedResources();
    }
    #endregion
}