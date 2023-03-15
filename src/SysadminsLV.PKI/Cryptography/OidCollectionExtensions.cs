using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Contains extension methods for <see cref="OidCollection"/> class.
/// </summary>
public static class OidCollectionExtensions {
    /// <summary>
    /// Gets a duplicate instance of <see cref="OidCollection"/> collection.
    /// </summary>
    /// <param name="oidCollection">Source collection.</param>
    /// <returns>
    ///     A copy of source collection. Source and destination collections will hold same references to collection elements.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    ///     <strong>oidCollection</strong> parameter is null.
    /// </exception>
    public static OidCollection Duplicate(this OidCollection oidCollection) {
        if (oidCollection == null) {
            throw new ArgumentNullException(nameof(oidCollection));
        }

        var retValue = new OidCollection();
        foreach (Oid extension in oidCollection) {
            retValue.Add(extension);
        }

        return retValue;
    }
}
