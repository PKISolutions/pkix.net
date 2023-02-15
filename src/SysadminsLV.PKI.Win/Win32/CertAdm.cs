using System;
using System.Runtime.InteropServices;
using PKI.Structs;

namespace SysadminsLV.PKI.Win32 {
    /// <summary>
    /// Contains only unmanaged function p/invoke definitions which are defined in <strong>"Certadm.dll".dll</strong> library.
    /// </summary>
    public static class CertAdm {
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CertSrvIsServerOnline(
            [In] String pwszServerName,
            [Out] out Boolean pfServerOnline
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvBackupPrepare(
            [In] String pwszServerName,
            [In] UInt32 grbitJet,
            [In] UInt32 dwBackupFlags,
            [In, Out] ref IntPtr phbc
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvBackupGetDatabaseNames(
            [In] IntPtr hbc,
            [In, Out] ref IntPtr ppwszzAttachmentInformation,
            [In, Out] ref UInt32 pcbSize
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvBackupGetBackupLogs(
            [In] IntPtr hbc,
            [In, Out] ref IntPtr ppwszzBackupLogFiles,
            [In, Out] ref UInt32 pcbSize
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvBackupGetDynamicFileList(
            [In] IntPtr hbc,
            [In, Out] ref IntPtr ppwszzFileList,
            [In, Out] ref UInt32 pcbSize
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvBackupOpenFile(
            [In] IntPtr hbc,
            [In] String pwszAttachmentName,
            [In] Int32 cbReadHintSize,
            [In, Out] ref Int64 pliFileSize
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvBackupRead(
            [In] IntPtr hbc,
            [Out] IntPtr pvBuffer,
            [In] Int32 cbBuffer,
            [In, Out] ref Int32 pcbRead
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvBackupClose(
            [In] IntPtr hbc
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvBackupTruncateLogs(
            [In] IntPtr hbc
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvBackupEnd(
            [In] IntPtr phbc
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvBackupFree(
            [In] IntPtr pv
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvRestorePrepare(
            String pwszServerName,
            UInt32 dwRestoreFlags,
            ref IntPtr phbc
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvRestoreGetDatabaseLocations(
            IntPtr hbc,
            ref IntPtr ppwszzDatabaseLocationList,
            ref UInt32 pcbSize
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvRestoreRegister(
            IntPtr hbc,
            String pwszCheckPointFilePath,
            String pwszLogPath,
            Certbcli.CSEDB_RSTMAP[] rgrstmap,
            Int32 crstmap,
            String pwszBackupLogPath,
            UInt32 genLow,
            UInt32 genHigh
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvRestoreRegisterComplete(
            IntPtr hbc,
            Int32 hrRestoreState
        );
        [DllImport("Certadm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertSrvRestoreEnd(
            IntPtr hbc
        );
    }
}
