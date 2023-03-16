using System.Collections;
using System.DirectoryServices;
using SysadminsLV.PKI.Management.ActiveDirectory;

namespace SysadminsLV.PKI.Utils.CLRExtensions;

/// <summary>
/// Contains extension methods for <see cref="PropertyCollection"/> class.
/// </summary>
public static class PropertyCollectionExtensions {
    /// <summary>
    /// Gets an instance of <see cref="DsPropertyCollection"/> with copied values.
    /// </summary>
    /// <param name="props"></param>
    /// <returns></returns>
    public static DsPropertyCollection ToDsPropertyCollection(this PropertyCollection props) {
        var retValue = new DsPropertyCollection();
        foreach (DictionaryEntry entry in props) {
            retValue.Add(entry.Key.ToString(), entry.Value);
        }

        return retValue;
    }
}
