using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using CERTCLILib;

namespace SysadminsLV.PKI.Dcom.Implementations {
    /// <summary>
    /// Represents a static Windows implementation for <see cref="ICertConfigD"/> interface.
    /// </summary>
    public static class  CertConfigD2 {
        static String getConfig(CertConfigOption option) {
            var certConfig = new CCertConfigClass();
            try {
                return certConfig.GetConfig((Int32)option);
            } catch {
                return null;
            } finally {
                Marshal.FinalReleaseComObject(certConfig);
            }
        }

        /// <inheritdoc cref="ICertConfigD.GetDefaultConfig"/>
        public static String GetDefaultConfig() {
            return getConfig(CertConfigOption.DefaultConfig);
        }
        /// <inheritdoc cref="ICertConfigD.GetFirstConfig"/>
        public static String GetFirstConfig() {
            return getConfig(CertConfigOption.FirstConfig);
        }
        /// <inheritdoc cref="ICertConfigD.GetLocalConfig"/>
        public static String GetLocalConfig() {
            return getConfig(CertConfigOption.LocalConfig);
        }
        /// <inheritdoc cref="ICertConfigD.GetLocalActiveConfig"/>
        public static String GetLocalActiveConfig() {
            return getConfig(CertConfigOption.LocalActiveConfig);
        }
        /// <inheritdoc cref="ICertConfigD.GetUIConfig"/>
        public static String GetUIConfig() {
            return getConfig(CertConfigOption.UIPickConfig);
        }
        /// <inheritdoc cref="ICertConfigD.GetUISkipLocalConfig"/>
        public static String GetUISkipLocalConfig() {
            return getConfig(CertConfigOption.UIPickConfigSkipLocalCA);
        }
        /// <inheritdoc cref="ICertConfigD.EnumConfigEntries"/>
        public static ICertConfigEntryD[] EnumConfigEntries() {
            var list = new List<ICertConfigEntryD>();
            var certConfig = new CCertConfigClass();
            while (certConfig.Next() >= 0) {
                list.Add(new CertConfigEntryD(certConfig));
            }
            Marshal.FinalReleaseComObject(certConfig);
            return list.ToArray();
        }
        /// <inheritdoc cref="ICertConfigD.FindConfigEntryByCertificateName"/>
        public static ICertConfigEntryD FindConfigEntryByCertificateName(String caName) {
            var certConfig = new CCertConfigClass();

            while (certConfig.Next() >= 0) {
                try {
                    if (certConfig.GetField("CommonName").Equals(caName, StringComparison.CurrentCultureIgnoreCase)) {
                        var entry = new CertConfigEntryD(certConfig);
                        Marshal.FinalReleaseComObject(certConfig);
                        return entry;
                    }
                } catch { }
            }
            return null;
        }
        /// <inheritdoc cref="ICertConfigD.FindConfigEntryByServerName"/>
        public static ICertConfigEntryD FindConfigEntryByServerName(String computerName) {
            var certConfig = new CCertConfigClass();

            while (certConfig.Next() >= 0) {
                try {
                    if (certConfig.GetField("Server").Equals(computerName, StringComparison.OrdinalIgnoreCase)) {
                        var entry = new CertConfigEntryD(certConfig);
                        Marshal.FinalReleaseComObject(certConfig);
                        return entry;
                    }
                } catch { }
            }
            return null;
        }
    }
}