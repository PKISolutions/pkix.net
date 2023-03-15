using System;
using System.Collections.Generic;
using System.Linq;

namespace SysadminsLV.PKI.Utils.CLRExtensions;
static class DictionaryExtensions {
    public static TValue GetDsScalarValue<TValue>(this IDictionary<String, Object> dictionary, String key) {
        if (!dictionary.ContainsKey(key)) {
            return default;
        }

        try {
            return (TValue)dictionary[key];
        } catch {
            return default;
        }
    }
    public static TValue[] GetDsCollectionValue<TValue>(this IDictionary<String, Object> dictionary, String key) {
        if (!dictionary.ContainsKey(key) || dictionary[key] == null) {
            return Array.Empty<TValue>();
        }

        try {
            if (dictionary[key] is TValue[] value) {
                return value;
            }
            if (dictionary[key] is TValue scalarValue) {
                return new[] { scalarValue };
            }
            if (dictionary[key] is Object[] objects) {
                return objects.Cast<TValue>().ToArray();
            }
        } catch {
            return Array.Empty<TValue>();
        }

        return Array.Empty<TValue>();
    }
}
