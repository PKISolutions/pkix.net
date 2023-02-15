using System;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Represents a wrapper interface for Microsoft
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/certcli/nn-certcli-icertconfig">ICertConfig</see> COM interface.
    /// </summary>
    public interface ICertConfigD {
        /// <summary>
        /// Retrieves the default certification authority.
        /// </summary>
        /// <returns>
        /// Certification Authority configuration string in a 'HostName\CA Certificate Name' form. If no server found, the method returns NULL.
        /// </returns>
        String GetDefaultConfig();
        /// <summary>
        /// Returns the first certification authority.
        /// </summary>
        /// <returns>
        /// Certification Authority configuration string in a 'HostName\CA Certificate Name' form. If no server found, the method returns NULL.
        /// </returns>
        String GetFirstConfig();
        /// <summary>
        /// Retrieves the local certification authority.
        /// </summary>
        /// <returns>
        /// Certification Authority configuration string in a 'HostName\CA Certificate Name' form. If no server found, the method returns NULL.
        /// </returns>
        String GetLocalConfig();
        /// <summary>
        /// Retrieves the local certification authority if it is running.
        /// </summary>
        /// <returns>
        /// Certification Authority configuration string in a 'HostName\CA Certificate Name' form. If no server found, the method returns NULL.
        /// </returns>
        String GetLocalActiveConfig();
        /// <summary>
        /// Displays a user interface that allows the user to select a certification authority.
        /// </summary>
        /// <returns>
        /// Certification Authority configuration string in a 'HostName\CA Certificate Name' form. If no server found, the method returns NULL.
        /// </returns>
        String GetUIConfig();
        /// <summary>
        /// Displays a user interface that allows the user to select a certification authority. The UI excludes any local
        /// certification authority. This exclusion is useful during subordinate certification authority certificate renewal
        /// when the subordinate certification authority certificate request is submitted to a certification authority other
        /// than the current certification authority.
        /// </summary>
        /// <returns>
        /// Certification Authority configuration string in a 'HostName\CA Certificate Name' form. If no server found, the method returns NULL.
        /// </returns>
        String GetUISkipLocalConfig();

        /// <summary>
        /// Gets an array of discovered certification authority configuration entries.
        /// </summary>
        /// <returns>An array of discovered certification authority configuration entries. An empty array is returned if no entries found.</returns>
        ICertConfigEntryD[] EnumConfigEntries();
        /// <summary>
        /// Finds Certification Authority configuration entry by CA certificate name (common name).
        /// </summary>
        /// <param name="caName">CA certificate name.</param>
        /// <returns>Configuration entry if CA config entry is found that matches search criteria. Otherwise returns NULL.</returns>
        ICertConfigEntryD FindConfigEntryByCertificateName(String caName);
        /// <summary>
        /// Finds Certification Authority configuration entry by CA host name.
        /// </summary>
        /// <param name="computerName">CA host name FQDN.</param>
        /// <returns>Configuration entry if CA config entry is found that matches search criteria. Otherwise returns NULL.</returns>
        ICertConfigEntryD FindConfigEntryByServerName(String computerName);
    }
}