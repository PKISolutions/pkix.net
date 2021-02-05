using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using SysadminsLV.PKI.Dcom;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a Windows Registry-based Certification Authority configuration implementation of <see cref="ICertRegManagerD"/> interface.
    /// This class uses direct Windows Registry access to read and write configuration values. For remote access, this class requires
    /// 'Remote Registry' to be running on remote server. Caller must have appropriate permissions to connect to remote registry.
    /// </summary>
    public class CertSrvRegManager : ICertRegManagerD {
        const String CERTSRV_CONFIG = @"System\CurrentControlSet\Services\CertSvc\Configuration\";
        const String CERTSRV_ACTIVE = "Active";
        const String FAKE_VALUE = "FAKE_VALUE";
        String runtimePath;

        /// <summary>
        /// Initializes a new instance of <strong>CertSrvRegManager</strong> from server name where Certification Authority is installed.
        /// </summary>
        /// <param name="serverName">Certification Authority host name.</param>
        public CertSrvRegManager(String serverName) {
            ComputerName = serverName ?? throw new ArgumentNullException(nameof(serverName));
            ActiveConfig = readActiveConfig();
            runtimePath = CERTSRV_CONFIG;
        }
        

        /// <inheritdoc />
        public String ComputerName { get; }
        /// <inheritdoc />
        public Boolean IsAccessible { get; private set; }
        /// <inheritdoc />
        public String ActiveConfig { get; private set; }

        String readActiveConfig() {
            try {
                using (RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, ComputerName, RegistryView.Default)) {
                    RegistryKey root = key.OpenSubKey(CERTSRV_CONFIG, false);
                    String active = (String)root?.GetValue(CERTSRV_ACTIVE, FAKE_VALUE);
                    root?.Close();
                    if (FAKE_VALUE.Equals(active)) {
                        throw new FileNotFoundException();
                    }
                    IsAccessible = true;
                    return active;
                }
            } catch {
                IsAccessible = false;
            }

            return null;
        }

        /// <inheritdoc />
        public Object GetConfigEntry(String entryName, String node = null) {
            if (entryName == null) {
                throw new ArgumentNullException(nameof(entryName));
            }
            if (String.Empty.Equals(entryName)) {
                throw new ArgumentException("'entryName' parameter cannot be empty string.");
            }

            String subKey = runtimePath;
            if (!String.IsNullOrWhiteSpace(node)) {
                subKey = runtimePath + node;
            }

            using (RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, ComputerName, RegistryView.Default)) {
                RegistryKey root = key.OpenSubKey(runtimePath, false);
                Object value = root?.GetValue(subKey, FAKE_VALUE);
                root?.Close();
                if (value == null || FAKE_VALUE.Equals(value)) {
                    return null;
                }
                return value;
            }
        }
        /// <inheritdoc />
        public T GetConfigEntry<T>(String entryName, String node = null) {
            if (entryName == null) {
                throw new ArgumentNullException(nameof(entryName));
            }
            if (String.Empty.Equals(entryName)) {
                throw new ArgumentException("'entryName' parameter cannot be empty string.");
            }

            String subKey = runtimePath;
            if (!String.IsNullOrWhiteSpace(node)) {
                subKey = runtimePath + node;
            }

            using (RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, ComputerName, RegistryView.Default)) {
                RegistryKey root = key.OpenSubKey(subKey, false);
                Object value = root?.GetValue(entryName, FAKE_VALUE);
                root?.Close();
                if (value == null || FAKE_VALUE.Equals(value)) {
                    throw new FileNotFoundException();
                }
                return (T)value;
            }
        }
        /// <inheritdoc />
        public String GetStringConfigEntry(String entryName, String node = null) {
            return GetConfigEntry<String>(entryName, node);
        }
        /// <inheritdoc />
        public String[] GetMultiStringConfigEntry(String entryName, String node = null) {
            return GetConfigEntry<String[]>(entryName, node);
        }
        /// <inheritdoc />
        public Int32 GetNumericConfigEntry(String entryName, String node = null) {
            return GetConfigEntry<Int32>(entryName, node);
        }
        /// <inheritdoc />
        public Boolean GetBooleanConfigEntry(String entryName, String node = null) {
            return GetConfigEntry<Int32>(entryName, node) != 0;
        }
        /// <inheritdoc />
        public Byte[] GetBinaryConfigEntry(String entryName, String node = null) {
            return GetConfigEntry<Byte[]>(entryName, node);
        }
        /// <inheritdoc />
        public void SetConfigEntry(Object data, String entryName, String node = null) {
            if (data == null) {
                throw new ArgumentNullException(nameof(data));
            }

            using (RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, ComputerName, RegistryView.Default)) {
                RegistryKey root = key.OpenSubKey(runtimePath, true);
                if (root == null) {
                    throw new FileNotFoundException();
                }

                Object writeValue = data;
                RegistryValueKind type;
                switch (data) {
                    case String _:
                        type = RegistryValueKind.String;
                        break;
                    case Int32 _:
                        type = RegistryValueKind.DWord;
                        break;
                    case Boolean b:
                        writeValue = b ? 1 : 0;
                        type = RegistryValueKind.DWord;
                        break;
                    case IEnumerable<String> array:
                        writeValue = array.ToArray();
                        type = RegistryValueKind.MultiString;
                        break;
                    case IEnumerable<Byte> array:
                        writeValue = array.ToArray();
                        type = RegistryValueKind.Binary;
                        break;
                    default:
                        throw new ArgumentException();
                }
                root.SetValue(entryName, writeValue, type);
            }
        }
        /// <inheritdoc />
        public void DeleteConfigEntry(String entryName, String node = null) {
            if (entryName == null) {
                throw new ArgumentNullException(nameof(entryName));
            }
            if (String.Empty.Equals(entryName)) {
                throw new ArgumentException("'entryName' parameter cannot be empty string.");
            }

            String subKey = runtimePath;
            if (!String.IsNullOrWhiteSpace(node)) {
                subKey = runtimePath + node;
            }

            using (RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, ComputerName, RegistryView.Default)) {
                RegistryKey root = key.OpenSubKey(subKey, true);
                root?.DeleteValue(entryName);
                root?.Close();
            }
        }
        /// <inheritdoc />
        public void SetRootNode(Boolean forceActive) {
            ActiveConfig = readActiveConfig() ?? ActiveConfig;
            runtimePath = forceActive
                ? CERTSRV_CONFIG + ActiveConfig + "\\"
                : CERTSRV_CONFIG;
        }
    }
}