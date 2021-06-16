using System;

namespace SysadminsLV.PKI.Dcom.Implementations {
    /// <summary>
    /// Represents Windows implementation for <see cref="ICertConfigD"/> interface. This class represents an instance implementation
    /// of <see cref="CertConfigD2"/> static class and can be used in dependency injection scenarios.
    /// </summary>
    public class CertConfigD : ICertConfigD {
        /// <inheritdoc />
        public String GetDefaultConfig() {
            return CertConfigD2.GetDefaultConfig();
        }
        /// <inheritdoc />
        public String GetFirstConfig() {
            return CertConfigD2.GetFirstConfig();
        }
        /// <inheritdoc />
        public String GetLocalConfig() {
            return CertConfigD2.GetLocalConfig();
        }
        /// <inheritdoc />
        public String GetLocalActiveConfig() {
            return CertConfigD2.GetLocalActiveConfig();
        }
        /// <inheritdoc />
        public String GetUIConfig() {
            return CertConfigD2.GetUIConfig();
        }
        /// <inheritdoc />
        public String GetUISkipLocalConfig() {
            return CertConfigD2.GetUISkipLocalConfig();
        }
        /// <inheritdoc />
        public ICertConfigEntryD[] EnumConfigEntries() {
            return CertConfigD2.EnumConfigEntries();
        }
        /// <inheritdoc />
        public ICertConfigEntryD FindConfigEntryByCertificateName(String caName) {
            return CertConfigD2.FindConfigEntryByCertificateName(caName);
        }
        /// <inheritdoc />
        public ICertConfigEntryD FindConfigEntryByServerName(String computerName) {
            return CertConfigD2.FindConfigEntryByServerName(computerName);
        }
    }
}