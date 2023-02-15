using System;
using Microsoft.Win32;
using PKI.Exceptions;
using PKI.Utils;
using SysadminsLV.PKI.Management.CertificateServices;

namespace PKI.CertificateServices.Flags {
    /// <summary>
    /// Contains information about Key Recovery Agent flags enabled on CA server.
    /// </summary>
    public class KRAFlag {
        String configString;
        CertSrvPlatformVersion version;

        /// <param name="certificateAuthority">Specifies an existing <see cref="CertificateAuthority"/> object.</param>
        /// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
        public KRAFlag(CertificateAuthority certificateAuthority) {
            if (!String.IsNullOrEmpty(certificateAuthority.Name)) {
                m_initialize(certificateAuthority);
            } else { throw new UninitializedObjectException(); }
        }

        /// <summary>
        /// Gets the common name of the Certification Authority in a sanitized form as specified in
        /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
        /// </summary>
        public String Name { get; private set; }
        /// <summary>
        /// Gets the display name of the Certification Authority (sanitized characters are decoded to textual characters).
        /// </summary>
        public String DisplayName { get; private set; }
        /// <summary>
        /// Gets the host fully qualified domain name (FQDN) of the server where Certification Authority is installed.
        /// </summary>
        public String ComputerName { get; private set; }
        /// <summary>
        /// Gets enabled Key Recovery Agent flags. Possible flags are listed in <see cref="KRAFlagEnum"/>.
        /// </summary>
        public KRAFlagEnum KRAFlags { get; private set; }
        /// <summary>
        /// Indicates whether the object was modified after it was instantiated.
        /// </summary>
        public Boolean IsModified { get; private set; }

        void m_initialize(CertificateAuthority certificateAuthority) {
            Name = certificateAuthority.Name;
            DisplayName = certificateAuthority.DisplayName;
            ComputerName = certificateAuthority.ComputerName;
            configString = certificateAuthority.ConfigString;
            version = certificateAuthority.Version;
            if (CryptoRegistry.Ping(ComputerName)) {
                KRAFlags = (KRAFlagEnum)CryptoRegistry.GetRReg("KRAFlags", Name, ComputerName);
            } else {
                if (CertificateAuthority.Ping(ComputerName)) {
                    KRAFlags = (KRAFlagEnum)CryptoRegistry.GetRegFallback(configString, "", "KRAFlags");
                } else {
                    ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                    e.Data.Add(nameof(e.Source), (OfflineSource)3);
                    throw e;
                }
            }
        }

        /// <summary>
        /// Adds Key Recovery Agent (KRA) flags to enable on a specified Certification Authority. Multiple
        /// flags can be added at the time.
        /// </summary>
        /// <param name="flags">One or more flags defined in <see cref="KRAFlagEnum"/> enumeration.</param>
        /// <exception cref="ArgumentException">The data in the <strong>flags</strong> parameter
        /// contains Key Recovery Agent flags that are not supported by a current Certification Authority version.</exception>
        public void Add(KRAFlagEnum flags) {
            Int32[] existing = EnumFlags.GetEnabled(typeof(KRAFlagEnum),(Int32)KRAFlags);
            Int32[] newf = EnumFlags.GetEnabled(typeof(KRAFlagEnum), (Int32)flags);
            if (version == CertSrvPlatformVersion.Win2003 && ((Int32)flags & (Int32)KRAFlagEnum.DisableUseDefaultProvider) != 0) {
                throw new ArgumentException();
            }
            foreach (Int32 item in newf) {
                if (!EnumFlags.Contains(existing, item)) {
                    KRAFlags |= (KRAFlagEnum)item;
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Removes Key Recovery Agent (KRA) flags from a specified Certification Authority. Multiple
        /// flags can be removed at the time.
        /// </summary>
        /// <param name="flags">One or more flags defined in <see cref="KRAFlagEnum"/> enumeration.</param>
        public void Remove(KRAFlagEnum flags) {
            Int32[] existing = EnumFlags.GetEnabled(typeof(KRAFlagEnum), (Int32)KRAFlags);
            Int32[] newf = EnumFlags.GetEnabled(typeof(KRAFlagEnum), (Int32)flags);
            foreach (Int32 item in newf) {
                if (EnumFlags.Contains(existing, item)) {
                    KRAFlags = (KRAFlagEnum)((Int32)KRAFlags - item);
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Restores default Key Recovery Agent flags on a specified Certification Authority. The method do not
        /// writes default flags to a configuration. After calling this method call <see cref="SetInfo"/> method to write
        /// the values to a configuration.
        /// </summary>
        /// <remarks>By default no Key Recovery Agent flags are set.</remarks>
        public void Restore() {
            KRAFlags = 0;
            IsModified = true;
        }
        /// <summary>
        /// Updates Key Recovery Agent flags by writing them to Certification Authority.
        /// </summary>
        /// <param name="restart">
        /// Indicates whether to restart certificate services to immediately apply changes. Updated settings has no effect
        /// until CA service is restarted.
        /// </param>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller do not have sufficient permissions to make changes in the CA configuration.
        /// </exception>
        /// <exception cref="ServerUnavailableException">
        /// The target CA server could not be contacted via remote registry and RPC protocol.
        /// </exception>
        /// <returns>
        /// <strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
        /// and the method returns <strong>False</strong>.
        /// </returns>
        /// <remarks>The caller must have <strong>Administrator</strong> permissions on the target CA server.</remarks>
        public Boolean SetInfo(Boolean restart) {
            if (IsModified) {
                if (CryptoRegistry.Ping(ComputerName)) {
                    CryptoRegistry.SetRReg((Int32)KRAFlags, "KRAFlags", RegistryValueKind.DWord, Name, ComputerName);
                    if (restart) { CertificateAuthority.Restart(ComputerName); }
                    IsModified = false;
                    return true;
                }
                if (CertificateAuthority.Ping(ComputerName)) {
                    CryptoRegistry.SetRegFallback(configString, String.Empty, "KRAFlags", (Int32)KRAFlags);
                    if (restart) { CertificateAuthority.Restart(ComputerName); }
                    IsModified = false;
                    return true;
                }
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), (OfflineSource)3);
                throw e;
            }
            return false;
        }
    }
}
