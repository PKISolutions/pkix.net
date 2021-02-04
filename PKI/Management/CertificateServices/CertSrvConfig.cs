using System;
using PKI.CertificateServices;
using PKI.Exceptions;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents base class for Certification Authority configuration. This is abstract class and cannot be instantiated directly.
    /// </summary>
    public abstract class CertSrvConfig {
        /// <summary>
        /// Initializes a new instance of <strong>CertSrvConfig</strong> from a string that contains a computer name where Certification Authority is installed.
        /// </summary>
        /// <param name="computerName">computer name where Certification Authority is installed.</param>
        /// <exception cref="ArgumentException"><strong>computerName</strong> parameter cannot be null or empty string.</exception>
        /// <exception cref="ServerUnavailableException">Certification Authority is not accessible via any supported protocol.</exception>
        protected CertSrvConfig(String computerName) {
            if (String.IsNullOrWhiteSpace(computerName)) {
                throw new ArgumentException(nameof(computerName));
            }

            ComputerName = computerName;
            ConfigManager = new CertSrvConfigUtil(ComputerName);

            if (!ConfigManager.RegistryOnline && !ConfigManager.DcomOnline) {
                var e = new ServerUnavailableException(ComputerName);
                e.Data.Add(nameof(e.Source), OfflineSource.All);

                throw e;
            }
        }

        /// <summary>
        /// Gets the certification authority computer name.
        /// </summary>
        public String ComputerName { get; }
        /// <summary>
        /// Indicates whether the object was modified after it was instantiated. This member is set to <strong>False</strong> upon successful changes commit.
        /// </summary>
        public Boolean IsModified { get; protected set; }
        /// <summary>
        /// Gets the CA configuration read/write manager used by implementers to read and write configuration.
        /// </summary>
        protected CertSrvConfigUtil ConfigManager { get; }

        /// <summary>
        /// Updates Certification Authority configuration on a server.
        /// </summary>
        /// <param name="restart">
        ///		Indicates whether to restart certificate services to immediately apply changes. Updated settings has no effect
        ///		until CA service is restarted.
        /// </param>
        /// <exception cref="ServerUnavailableException">
        ///		The target CA server could not be contacted via remote registry and RPC protocol.
        /// </exception>
        /// <returns>
        ///		<strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
        ///		and the method returns <strong>False</strong>.
        /// </returns>
        /// <remarks>
        ///		The caller must have <strong>Administrator</strong> permissions on the target CA server.
        /// </remarks>
        public Boolean Commit(Boolean restart) {
            if (!IsModified) {
                return IsModified;
            }

            IsModified = false;
            if (restart) {
                CertificateAuthority.Restart(ComputerName);
            }

            return true;
        }
    }
}