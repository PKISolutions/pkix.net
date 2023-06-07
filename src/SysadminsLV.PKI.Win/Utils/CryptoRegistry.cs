using System;
using System.Collections.Generic;
using System.ComponentModel;
using CERTADMINLib;
using Microsoft.Win32;

namespace SysadminsLV.PKI.Utils;
static class CryptoRegistry {

#region Local registry
    const String ContextAutoEnrollment = @"SOFTWARE\Policies\Microsoft\Cryptography";
    public static Object GetLKey(String context, Boolean userContext) {
        RegistryKey key;
        switch (context) {
            case "Autoenrollment":
                key = userContext
                    ? Registry.CurrentUser.OpenSubKey($@"{ContextAutoEnrollment}\AutoEnrollment")
                    : Registry.LocalMachine.OpenSubKey($@"{ContextAutoEnrollment}\AutoEnrollment");
                if (key == null) { return null; }
                Int32 result = (Int32)key.GetValue("AEPolicy");
                key.Close();
                return result;
            default: return null;
        }
    }
#endregion

#region Native remote registry methods
    public static Boolean Ping(String computerName) {
        try {
            RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName);
            key.OpenSubKey(@"System\CurrentControlSet\Services\CertSvc\Configuration\", false);
            key.Close();
        } catch { return false; }
        return true;
    }
    public static Object GetRReg(
        String entry,
        String caName,
        String computerName,
        String node = @"System\CurrentControlSet\Services\CertSvc\Configuration\"
    ) {
        RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName);
        key = caName == String.Empty
            ? key.OpenSubKey(node, false)
            : key.OpenSubKey(node + caName, false);
        if (key != null) {
            Object retn = key.GetValue(entry, "false");
            if (retn.ToString() != "false") {
                key.Close();
                return retn;
            }
            key.Close();
            throw new Win32Exception(2);
        }
        throw new Win32Exception(2);
    }
    public static void SetRReg(
        Object value,
        String entry,
        RegistryValueKind type,
        String caName,
        String computerName,
        String node = @"System\CurrentControlSet\Services\CertSvc\Configuration\"
    ) {
        RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName);
        key = caName == String.Empty
            ? key.OpenSubKey(node, true)
            : key.OpenSubKey(node + caName, true);
        try {
            key?.SetValue(entry, value, type);
        }
        finally {
            key?.Close();
        }
    }
    public static void SetRReg(
        List<String> value,
        String entry,
        String caName,
        String computerName,
        String node = @"System\CurrentControlSet\Services\CertSvc\Configuration\"
    ) {
        RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName);
        key = caName == String.Empty
            ? key.OpenSubKey(node, true)
            : key.OpenSubKey(node + caName, true);
        try {
            key?.SetValue(entry, value.ToArray(), RegistryValueKind.MultiString);
        }
        finally {
            key?.Close();
        }
    }
    public static void SetRReg(
        Byte[] value,
        String entry,
        String caName,
        String computerName,
        String node = @"System\CurrentControlSet\Services\CertSvc\Configuration\"
    ) {
        RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName);
        key = caName == String.Empty
            ? key.OpenSubKey(node, true)
            : key.OpenSubKey(node + caName, true);
        try {
            key?.SetValue(entry, value, RegistryValueKind.Binary);
        }
        finally {
            key?.Close();
        }
    }
#endregion

#region ICertAdmin registry methods
    public static Object GetRegFallback(
        String configString,
        String node,
        String entry
    ) {
        CCertAdmin CertAdmin = new CCertAdmin();
        try {
            Object retn = CertAdmin.GetConfigEntry(configString, node, entry);
            CryptographyUtils.ReleaseCom(CertAdmin);
            return retn;
        } catch (Exception e) {
            throw ErrorHelper.ComExceptionHandler(e);
        } finally {
            CryptographyUtils.ReleaseCom(CertAdmin);
        }
    }
    public static void SetRegFallback(
        String configString,
        String node,
        String entry,
        Object value
    ) {
        CCertAdmin CertAdmin = new CCertAdmin();
        try {
            CertAdmin.SetConfigEntry(configString, node, entry, value);
        } catch (Exception e) {
            throw ErrorHelper.ComExceptionHandler(e);
        } finally {
            CryptographyUtils.ReleaseCom(CertAdmin);
        }
    }
    #endregion
}
