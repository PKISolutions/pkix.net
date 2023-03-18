using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace SysadminsLV.PKI.Management;
class RegistryReader {
    String contextKey;
    
    public RegistryReader(String context = null) {
        contextKey = context;
    }

    public void SetContextKey(String keyName) {
        contextKey = keyName;
    }
    public void SetContextSubKey(String subKeyName) {
        contextKey += "\\" + subKeyName;
    }

    public Boolean TestSubKeyExists(String subKeyName) {
        using RegistryKey rk = getRegistryKey().OpenSubKey(subKeyName);
        return rk != null;
    }

    public Boolean TestValueExist(String valueName) {
        using RegistryKey rk = getRegistryKey();
        return rk?.GetValue(valueName) != null;
    }

    public IEnumerable<String> GetSubKeyNames() {
        using RegistryKey rk = getRegistryKey();
        return rk?.GetSubKeyNames();
    }

    public IEnumerable<String> GetValueNames() {
        using RegistryKey rk = getRegistryKey();
        return rk?.GetValueNames();
    }

    public Boolean GetBitValue(String valueName) {
        if (!TryGetBitValue(valueName, out Boolean data)) {
            throw new ArgumentException($"'{valueName}': Registry value could not be read.");
        }

        return data;
    }

    public Boolean TryGetBitValue(String valueName, out Boolean data) {
        data = false;
        Object value = getValue(valueName);
        if (value is null) {
            return false;
        }

        try {
            data = Convert.ToInt64(value) != 0;
            return true;
        } catch {
            return false;
        }
    }

    public String GetStringValue(String valueName) {
        if (!TryGetStringValue(valueName, out String data)) {
            throw new ArgumentException($"'{valueName}': Registry value could not be read.");
        }

        return data;
    }

    public String GetStringValue(String valueName, String defaultValue) {
        return !TryGetStringValue(valueName, out String data) ? defaultValue : data;
    }

    public Boolean TryGetStringValue(String valueName, out String data) {
        data = Convert.ToString(getValue(valueName));
        return !String.IsNullOrEmpty(data);
    }

    public Int32 GetDWordValue(String valueName) {
        if (!TryGetDWordValue(valueName, out Int32 data)) {
            throw new ArgumentException($"'{valueName}': Registry value could not be read.");
        }

        return data;
    }
    public TEnum GetEnumValue<TEnum>(String valueName) where TEnum : struct, Enum {
        return (TEnum)Enum.Parse(typeof(TEnum), Convert.ToInt64(GetQWordValue(valueName)).ToString());
    }

    public Int32 GetDWordValue(String valueName, Int32 defaultValue) {
        return !TryGetDWordValue(valueName, out Int32 data) ? defaultValue : data;
    }

    public Boolean TryGetDWordValue(String valueName, out Int32 data) {
        data = 0;
        Object value = getValue(valueName);
        if (value is null) {
            return false;
        }

        try {
            data = Convert.ToInt32(value);
            return true;
        } catch {
            return false;
        }
    }

    public Int64 GetQWordValue(String valueName) {
        if (!TryGetQWordValue(valueName, out Int64 data)) {
            throw new ArgumentException($"'{valueName}': Registry value could not be read.");
        }

        return data;
    }

    public Int64 GetQWordValue(String valueName, Int64 defaultValue) {
        return !TryGetQWordValue(valueName, out Int64 data) ? defaultValue : data;
    }

    public Boolean TryGetQWordValue(String valueName, out Int64 data) {
        data = 0;
        Object value = getValue(valueName);
        if (value is null) {
            return false;
        }

        try {
            data = Convert.ToInt64(value);
            return true;
        } catch {
            return false;
        }
    }

    public String[] GetMultiStringValue(String valueName) {
        if (!TryGetMultiStringValue(valueName, out String[] data)) {
            throw new ArgumentException($"'{valueName}': Registry value could not be read.");
        }

        return data;
    }

    public Boolean TryGetMultiStringValue(String valueName, out String[] data) {
        data = null;
        Object value = getValue(valueName);
        if (value is null) {
            return false;
        }

        try {
            data = (String[])value;
            return true;
        } catch {
            return false;
        }
    }

    public Byte[] GetBinaryValue(String valueName) {
        if (!TryGetBinaryValue(valueName, out Byte[] data)) {
            throw new ArgumentException($"'{valueName}': Registry value could not be read.");
        }

        return data;
    }

    public Boolean TryGetBinaryValue(String valueName, out Byte[] data) {
        data = null;
        Object value = getValue(valueName);
        if (value is null) {
            return false;
        }

        try {
            data = (Byte[])value;
            return true;
        } catch {
            return false;
        }
    }

    Object getValue(String valueName) {
        using RegistryKey rk = getRegistryKey();
        return rk?.GetValue(valueName);
    }

    RegistryKey getRegistryKey() {
        return Registry.LocalMachine.OpenSubKey(contextKey ?? String.Empty, RegistryKeyPermissionCheck.ReadSubTree);
    }

    public static Boolean TestKeyExists(String keyName) {
        using RegistryKey rk = Registry.LocalMachine.OpenSubKey(keyName);
        return rk != null;
    }
}