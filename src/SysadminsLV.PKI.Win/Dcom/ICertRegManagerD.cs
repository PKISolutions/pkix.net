using System;
using System.IO;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Represents a wrapper interface for Microsoft
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/certadm/nn-certadm-icertadmin2">ICertAdmin2</see> COM interface.
    /// </summary>
    public interface ICertRegManagerD {

        /// <summary>
        /// Gets the Certification Authority server name.
        /// </summary>
        String ComputerName { get; }
        /// <summary>
        /// Indicates whether the Certification Authority configuration is accessible.
        /// </summary>
        /// <remarks>
        /// If this member returns <strong>False</strong>, this may indicate that server cannot be reached using RPC/DCOM protocol.
        /// </remarks>
        Boolean IsAccessible { get; }
        /// <summary>
        /// Gets the active Certification Authority configuration.
        /// </summary>
        String ActiveConfig { get; }

        /// <summary>
        /// Gets the Certification Authority configuration registry entry value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="ArgumentNullException"><strong>entryName</strong> parameter is null.</exception>
        /// <exception cref="ArgumentException"><strong>entryName</strong> parameter is empty string.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        Object GetConfigEntry(String entryName, String node = null);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry value.
        /// </summary>
        /// <typeparam name="T">Expected registry value type. Can be String, String[], Int32 or Byte[].</typeparam>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="ArgumentNullException"><strong>entryName</strong> parameter is null.</exception>
        /// <exception cref="ArgumentException"><strong>entryName</strong> parameter is empty string.</exception>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns></returns>
        T GetConfigEntry<T>(String entryName, String node = null);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry string value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="ArgumentNullException"><strong>entryName</strong> parameter is null.</exception>
        /// <exception cref="ArgumentException"><strong>entryName</strong> parameter is empty string.</exception>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        String GetStringConfigEntry(String entryName, String node = null);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry multi-string value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="ArgumentNullException"><strong>entryName</strong> parameter is null.</exception>
        /// <exception cref="ArgumentException"><strong>entryName</strong> parameter is empty string.</exception>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        String[] GetMultiStringConfigEntry(String entryName, String node = null);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry numerical (integer) value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="ArgumentNullException"><strong>entryName</strong> parameter is null.</exception>
        /// <exception cref="ArgumentException"><strong>entryName</strong> parameter is empty string.</exception>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        Int32 GetNumericConfigEntry(String entryName, String node = null);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry boolean value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="ArgumentNullException"><strong>entryName</strong> parameter is null.</exception>
        /// <exception cref="ArgumentException"><strong>entryName</strong> parameter is empty string.</exception>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        Boolean GetBooleanConfigEntry(String entryName, String node = null);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry binary value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="ArgumentNullException"><strong>entryName</strong> parameter is null.</exception>
        /// <exception cref="ArgumentException"><strong>entryName</strong> parameter is empty string.</exception>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        Byte[] GetBinaryConfigEntry(String entryName, String node = null);
        /// <summary>
        /// Writes value to Certification Authority configuration. If value does not exist it will be created. Created registry value type
        /// is inferred from <strong>data</strong> parameter.
        /// </summary>
        /// <param name="data">Configuration value name to write.</param>
        /// <param name="entryName">Configuration value name to write to.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>data</strong> or <strong>entryName</strong> parameter is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     <strong>entryName</strong> parameter is empty string, or data type for <strong>data</strong> parameter is not accepted.
        ///     See remarks section for valid types.
        /// </exception>
        /// <remarks>
        /// Valid types for <strong>data</strong> parameter are:
        /// <list type="bullet">
        ///     <item>String</item>
        ///     <item>String[]</item>
        ///     <item>Int32</item>
        ///     <item>Boolean</item>
        ///     <item>Byte[]</item>
        /// </list>
        /// </remarks>
        void SetConfigEntry(Object data, String entryName, String node = null);
        /// <summary>
        /// Deletes Certification Authority configuration entry.
        /// </summary>
        /// <param name="entryName">Configuration value name to delete.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="ArgumentNullException"><strong>entryName</strong> parameter is null.</exception>
        /// <exception cref="ArgumentException"><strong>entryName</strong> parameter is empty string.</exception>
        void DeleteConfigEntry(String entryName, String node = null);

        /// <summary>
        /// Sets the root configuration node context. By executing this method, a <see cref="IsAccessible"/> property is updated to reflect the
        /// current state of Certification Authority DCOM connection.
        /// </summary>
        /// <param name="forceActive">
        ///     <strong>True</strong> if root configuration node must be set to active Certification Authority context. <strong>False</strong>
        ///     root configuration node is set to a parent Configuration node that is not specific to a CA.
        /// </param>
        void SetRootNode(Boolean forceActive);
    }
}