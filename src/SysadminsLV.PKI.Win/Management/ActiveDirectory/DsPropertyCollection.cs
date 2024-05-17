using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;

namespace SysadminsLV.PKI.Management.ActiveDirectory;

/// <summary>
/// Represents an extended version of <see cref="DirectoryEntry"/> properties.
/// </summary>
public sealed class DsPropertyCollection : IReadOnlyDictionary<String, Object> {
    readonly Dictionary<String, Object> _properties = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets non-nullable value from property collection. A default value is returned if key doesn't exist
    /// in dictionary or actual value is of different type. This method doesn't throw any exceptions.
    /// </summary>
    /// <typeparam name="TValue">
    /// Destination scalar value type. Can be:
    /// <list type="bullet">
    ///     <item><see cref="Byte"/></item>
    ///     <item><see cref="Int32"/></item>
    ///     <item><see cref="String"/></item>
    /// </list>
    /// </typeparam>
    /// <param name="key">Specifies the DS attribute name.</param>
    /// <returns>Value that represents requested attribute or default value.</returns>
    public TValue GetDsScalarValue<TValue>(String key) {
        if (!ContainsKey(key)) {
            return default;
        }

        try {
            if (this[key] == null) {
                return default;
            }
            return (TValue)this[key];
        } catch {
            return default;
        }
    }
    /// <summary>
    /// Gets non-nullable collection value from property collection. An empty array is returned if key doesn't exist
    /// in dictionary or actual value is of different type. This method doesn't throw any exceptions.
    /// </summary>
    /// <typeparam name="TValue">
    /// Destination array scalar value type. Can be:
    /// <list type="bullet">
    ///     <item><see cref="Byte"/></item>
    ///     <item><see cref="Int32"/></item>
    ///     <item><see cref="String"/></item>
    /// </list>
    /// </typeparam>
    /// <param name="key">Specifies the DS attribute name.</param>
    /// <returns>Value that represents requested attribute or default value.</returns>
    public TValue[] GetDsCollectionValue<TValue>(String key) {
        if (!ContainsKey(key) || this[key] == null) {
            return [];
        }

        try {
            switch (this[key]) {
                case TValue[] value:
                    return value;
                case TValue scalarValue:
                    return [scalarValue];
                case Object[] objects:
                    return objects.Cast<TValue>().ToArray();
            }
        } catch {
            return [];
        }

        return [];
    }

    /// <summary>
    /// Adds or updates the key in dictionary. A new key will be added if specified key doesn't exist in dictionary.
    /// Existing key value will be updated if specified key exists in dictionary.
    /// </summary>
    /// <param name="key">Key name.</param>
    /// <param name="value">Key value.</param>
    internal void Add(String key, Object value) {
        _properties[key] = value;
    }

    #region Explicit interface implementation
    /// <inheritdoc />
    public IEnumerator<KeyValuePair<String, Object>> GetEnumerator() => _properties.GetEnumerator();
    IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    /// <inheritdoc />
    public Int32 Count => _properties.Count;
    /// <inheritdoc />
    public Boolean ContainsKey(String key) => _properties.ContainsKey(key);
    /// <inheritdoc />
    public Boolean TryGetValue(String key, out Object value) => _properties.TryGetValue(key, out value);
    /// <inheritdoc />
    public Object this[String key] => _properties[key];
    /// <inheritdoc />
    public IEnumerable<String> Keys => _properties.Keys;
    /// <inheritdoc />
    public IEnumerable<Object> Values => _properties.Values;
    #endregion
}
