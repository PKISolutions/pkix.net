using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CERTADMINLib;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Dcom.Implementations;
/// <summary>
/// Represents a managed implementation of <see cref="ICertRegManagerD"/> interface and used to manage ADCS Certification Authority configuration.
/// This class uses RPC/DCOM transport to manage Certification Authority configuration.
/// </summary>
public class CertSrvRegManagerD : ICertRegManagerD {
    Boolean useActive;

    /// <summary>
    /// Initializes a new instance of <strong>CertSrvRegManagerD</strong> class from a Certification Authority configuration string.
    /// </summary>
    /// <param name="serverName"></param>
    /// <exception cref="ArgumentNullException">
    /// <strong>configString</strong> parameter is null.
    /// </exception>
    public CertSrvRegManagerD(String serverName) {
        ComputerName = serverName ?? throw new ArgumentNullException(nameof(serverName));
        ActiveConfig = readActiveConfig();
    }

    /// <inheritdoc />
    public String ComputerName { get; }
    /// <inheritdoc />
    public Boolean IsAccessible { get; private set; }
    /// <inheritdoc />
    public String ActiveConfig { get; private set; }

    String readActiveConfig() {
        ICertAdmin2 certAdmin = new CCertAdminClass();
        try {
            String active = (String)certAdmin.GetConfigEntry(ComputerName, String.Empty, "Active");
            IsAccessible = true;
            return active;
        } catch {
            IsAccessible = false;
        } finally {
            CryptographyUtils.ReleaseCom(certAdmin);
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

        ICertAdmin2 certAdmin = new CCertAdminClass();
        try {
            return useActive
                ? certAdmin.GetConfigEntry($"{ComputerName}\\{ActiveConfig}", node ?? String.Empty, entryName)
                : certAdmin.GetConfigEntry(ComputerName, String.Empty, entryName);
        } catch (Exception ex) {
            if (ex is FileNotFoundException) {
                return null;
            }
            throw;
        } finally {
            CryptographyUtils.ReleaseCom(certAdmin);
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

        ICertAdmin2 certAdmin = new CCertAdminClass();
        try {
            return (T)(useActive
                ? certAdmin.GetConfigEntry($"{ComputerName}\\{ActiveConfig}", node ?? String.Empty, entryName)
                : certAdmin.GetConfigEntry(ComputerName, String.Empty, entryName));
        } finally {
            CryptographyUtils.ReleaseCom(certAdmin);
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

        ICertAdmin2 certAdmin = new CCertAdminClass();
        try {
            switch (data) {
                case String _:
                case Int32 _:
                    if (useActive) {
                        certAdmin.SetConfigEntry($"{ComputerName}\\{ActiveConfig}", node ?? String.Empty, entryName, data);
                    } else {
                        certAdmin.SetConfigEntry(ComputerName, String.Empty, entryName, data);
                    }
                    break;
                case Boolean b:
                    if (useActive) {
                        certAdmin.SetConfigEntry($"{ComputerName}\\{ActiveConfig}", node ?? String.Empty, entryName, b ? 1 : 0);
                    } else {
                        certAdmin.SetConfigEntry(ComputerName, String.Empty, entryName, b ? 1 : 0);
                    }
                    break;
                case IEnumerable<String> array:
                    if (useActive) {
                        certAdmin.SetConfigEntry($"{ComputerName}\\{ActiveConfig}", node ?? String.Empty, entryName, array.ToArray());
                    } else {
                        certAdmin.SetConfigEntry(ComputerName, String.Empty, entryName, array.ToArray());
                    }
                    break;
                case IEnumerable<Byte> array:
                    if (useActive) {
                        certAdmin.SetConfigEntry($"{ComputerName}\\{ActiveConfig}", node ?? String.Empty, entryName, array.ToArray());
                    } else {
                        certAdmin.SetConfigEntry(ComputerName, String.Empty, entryName, array.ToArray());
                    }
                    break;
                default:
                    throw new ArgumentException();

            }
        } finally {
            CryptographyUtils.ReleaseCom(certAdmin);
        }
    }
    /// <inheritdoc />
    public void DeleteConfigEntry(String entryName, String node = null) {
        ICertAdmin2 certAdmin = new CCertAdminClass();
        try {
            if (useActive) {
                certAdmin.SetConfigEntry($"{ComputerName}\\{ActiveConfig}", node ?? String.Empty, entryName, null);
            } else {
                certAdmin.SetConfigEntry(ComputerName, String.Empty, entryName, null);
            }
        } catch (Exception ex) {
            if (!(ex is FileNotFoundException)) {
                throw;
            }
        } finally {
            CryptographyUtils.ReleaseCom(certAdmin);
        }
    }
    /// <inheritdoc />
    public void SetRootNode(Boolean forceActive) {
        useActive = forceActive;
        ActiveConfig = readActiveConfig() ?? ActiveConfig;
    }
}