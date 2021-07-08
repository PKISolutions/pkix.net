using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;
using PKI.Structs;
using SysadminsLV.PKI.Win32;

namespace PKI.Utils {
    static class Program {
        public static void Main(Byte[] pfxBytes, String password) {
            X509Certificate2 cert = importExportable(pfxBytes, password, machineScope: false);

            try {
                Boolean gotKey = Crypt32.CryptAcquireCertificatePrivateKey(
                    cert.Handle,
                    Wincrypt.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                    IntPtr.Zero,
                    out SafeNCryptKeyHandle keyHandle,
                    out UInt32 _,
                    out Boolean _);

                if (!gotKey) {
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                }

                using (var cngKey = CngKey.Open(keyHandle, 0)) {
                    Console.WriteLine(cngKey.ExportPolicy);

                    Console.WriteLine(
                        Convert.ToBase64String(
                            cngKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob)));
                }
            } finally {
                cert.Reset();
            }
        }

        static X509Certificate2 importExportable(Byte[] pfxBytes, String password, Boolean machineScope) {
            X509KeyStorageFlags flags = X509KeyStorageFlags.Exportable;

            flags |= machineScope
                ? X509KeyStorageFlags.MachineKeySet
                : X509KeyStorageFlags.UserKeySet;

            var cert = new X509Certificate2(pfxBytes, password, flags);

            try {
                Boolean gotKey = Crypt32.CryptAcquireCertificatePrivateKey(
                    cert.Handle,
                    Wincrypt.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                    IntPtr.Zero,
                    out SafeNCryptKeyHandle keyHandle,
                    out UInt32 keySpec,
                    out Boolean callerFree);

                if (!gotKey) {
                    keyHandle.Dispose();
                    throw new InvalidOperationException("No private key");
                }

                if (!callerFree) {
                    keyHandle.SetHandleAsInvalid();
                    keyHandle.Dispose();
                    throw new InvalidOperationException("Key is not persisted");
                }

                using (keyHandle) {
                    // -1 == CNG, otherwise CAPI
                    if (keySpec == UInt32.MaxValue) {
                        using (CngKey cngKey = CngKey.Open(keyHandle, CngKeyHandleOpenOptions.None)) {
                            // If the CNG->CAPI bridge opened the key then AllowPlaintextExport is already set.
                            if ((cngKey.ExportPolicy & CngExportPolicies.AllowPlaintextExport) == 0) {
                                fixExportability(cngKey, machineScope);
                            }
                        }
                    }
                }
            } catch {
                cert.Reset();
                throw;
            }

            return cert;
        }

        static void fixExportability(CngKey cngKey, Boolean machineScope) {
            String password = "1";
            Byte[] encryptedPkcs8 = ExportEncryptedPkcs8(cngKey, password, 1);
            String keyName = cngKey.KeyName;

            using (SafeNCryptProviderHandle provHandle = cngKey.ProviderHandle) {
                ImportEncryptedPkcs8Overwrite(
                    encryptedPkcs8,
                    keyName,
                    provHandle,
                    machineScope,
                    password);
            }
        }

        internal const String NCRYPT_PKCS8_PRIVATE_KEY_BLOB = "PKCS8_PRIVATEKEY";
        static readonly Byte[] s_pkcs12TripleDesOidBytes =
            Encoding.ASCII.GetBytes("1.2.840.113549.1.12.1.3\0");

        static Byte[] ExportEncryptedPkcs8(
            CngKey cngKey,
            String password,
            Int32 kdfCount) {
            var pbeParams = new nCrypt2.PbeParams {
                rgbSalt = Marshal.AllocHGlobal(nCrypt2.PbeParams.RgbSaltSize)
            };

            Byte[] salt = new Byte[nCrypt2.PbeParams.RgbSaltSize];

            using (var rng = RandomNumberGenerator.Create()) {
                rng.GetBytes(salt);
            }

            pbeParams.Params.cbSalt = salt.Length;
            Marshal.Copy(salt, 0, pbeParams.rgbSalt, salt.Length);
            pbeParams.Params.iIterations = kdfCount;

            // copy PBE params
            IntPtr pbeParamsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(pbeParams));
            Marshal.StructureToPtr(pbeParams, pbeParamsPtr, false);

            IntPtr passwordPtr = Marshal.StringToHGlobalUni(password);
            IntPtr oidPtr = Marshal.AllocHGlobal(s_pkcs12TripleDesOidBytes.Length);
            Marshal.Copy(s_pkcs12TripleDesOidBytes, 0, oidPtr, s_pkcs12TripleDesOidBytes.Length);


            IntPtr buffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(nCrypt2.BCryptBuffer)) * 3);
            IntPtr next = buffers;
            var buff = new nCrypt2.BCryptBuffer {
                BufferType = BCryptBufferType.PkcsSecret,
                cbBuffer = 2 * (password.Length + 1),
                pvBuffer = passwordPtr
            };
            if (IntPtr.Zero.Equals(buff.pvBuffer)) {
                buff.cbBuffer = 0;
            }
            Marshal.StructureToPtr(buff, next, false);
            buff = new nCrypt2.BCryptBuffer {
                BufferType = BCryptBufferType.PkcsAlgOid,
                cbBuffer = s_pkcs12TripleDesOidBytes.Length,
                pvBuffer = oidPtr
            };
            next += Marshal.SizeOf(typeof(nCrypt2.BCryptBuffer));
            Marshal.StructureToPtr(buff, next, false);

            buff = new nCrypt2.BCryptBuffer {
                BufferType = BCryptBufferType.PkcsAlgParam,
                cbBuffer = Marshal.SizeOf(typeof(nCrypt2.PbeParams)),
                pvBuffer = pbeParamsPtr
            };
            next += Marshal.SizeOf(typeof(nCrypt2.BCryptBuffer));
            Marshal.StructureToPtr(buff, next, false);

            var desc = new nCrypt2.NCryptBufferDesc {
                cBuffers = 3,
                pBuffers = buffers,
                ulVersion = 0,
            };
            IntPtr descPtr = Marshal.AllocHGlobal(Marshal.SizeOf(desc));
            Marshal.StructureToPtr(desc, descPtr, false);


            using (var keyHandle = cngKey.Handle) {
                Int32 result = NCrypt.NCryptExportKey(
                    keyHandle,
                    IntPtr.Zero,
                    NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                    descPtr,
                    null,
                    0,
                    out Int32 bytesNeeded,
                    0);

                if (result != 0) {
                    throw new Win32Exception(result);
                }

                Byte[] exported = new Byte[bytesNeeded];

                result = NCrypt.NCryptExportKey(
                    keyHandle,
                    IntPtr.Zero,
                    NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                    descPtr,
                    exported,
                    exported.Length,
                    out bytesNeeded,
                    0);

                if (result != 0) {
                    throw new Win32Exception(result);
                }

                if (bytesNeeded != exported.Length) {
                    Array.Resize(ref exported, bytesNeeded);
                }

                Marshal.FreeHGlobal(buffers);
                Marshal.FreeHGlobal(pbeParams.rgbSalt);
                Marshal.FreeHGlobal(pbeParamsPtr);
                Marshal.FreeHGlobal(descPtr);
                Marshal.ZeroFreeGlobalAllocUnicode(passwordPtr);
                Marshal.ZeroFreeGlobalAllocUnicode(oidPtr);

                return exported;
            }
        }

        static void ImportEncryptedPkcs8Overwrite(
            Byte[] encryptedPkcs8,
            String keyName,
            SafeNCryptProviderHandle provHandle,
            Boolean machineScope,
            String password) {

            // copy encrypted PKCS#8 to unmanaged memory
            IntPtr encryptedPkcs8Ptr = Marshal.AllocHGlobal(encryptedPkcs8.Length);
            Marshal.Copy(encryptedPkcs8, 0, encryptedPkcs8Ptr, encryptedPkcs8.Length);

            // copy key name to unmanaged memory
            IntPtr keyNamePtr = Marshal.StringToHGlobalUni(keyName);
            // copy password to unmanaged memory
            IntPtr passwordPtr = Marshal.StringToHGlobalUni(password);

            var buff1 = new nCrypt2.BCryptBuffer {
                BufferType = BCryptBufferType.PkcsSecret,
                cbBuffer = 2 * (password.Length + 1),
                pvBuffer = passwordPtr
            };
            if (IntPtr.Zero.Equals(buff1.pvBuffer)) {
                buff1.cbBuffer = 0;
            }
            var buff2 = new nCrypt2.BCryptBuffer {
                BufferType = BCryptBufferType.PkcsName,
                cbBuffer = 2 * (keyName.Length + 1),
                pvBuffer = keyNamePtr
            };

            Int32 buffSize = Marshal.SizeOf(typeof(nCrypt2.BCryptBuffer)) * 2;
            IntPtr buffers = Marshal.AllocHGlobal(buffSize);
            Marshal.StructureToPtr(buff1, buffers, false);
            IntPtr next = buffers + buffSize;
            Marshal.StructureToPtr(buff2, next, false);

            var desc = new nCrypt2.NCryptBufferDesc {
                cBuffers = 2,
                pBuffers = buffers,
                ulVersion = 0
            };

            NCryptImportFlags flags =
                NCryptImportFlags.NCRYPT_OVERWRITE_KEY_FLAG |
                NCryptImportFlags.NCRYPT_DO_NOT_FINALIZE_FLAG;

            if (machineScope) {
                flags |= NCryptImportFlags.NCRYPT_MACHINE_KEY_FLAG;
            }

            Int32 errorCode = NativeMethods.NCrypt.NCryptImportKey(
                provHandle,
                IntPtr.Zero,
                NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                ref desc,
                out SafeNCryptKeyHandle keyHandle,
                encryptedPkcs8Ptr,
                encryptedPkcs8.Length,
                flags);

            if (errorCode != 0) {
                keyHandle.Dispose();
                throw new Win32Exception(errorCode);
            }

            using (keyHandle) {
                using (var cngKey = CngKey.Open(keyHandle, CngKeyHandleOpenOptions.None)) {
                    const CngExportPolicies desiredPolicies =
                        CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport;

                    cngKey.SetProperty(
                        new CngProperty(
                            "Export Policy",
                            BitConverter.GetBytes((Int32)desiredPolicies),
                            CngPropertyOptions.Persist));

                    Int32 error = NCrypt.NCryptFinalizeKey(keyHandle, 0);

                    if (error != 0) {
                        throw new Win32Exception(error);
                    }
                }
            }

            Marshal.FreeHGlobal(buffers);
            Marshal.ZeroFreeGlobalAllocUnicode(encryptedPkcs8Ptr);
            Marshal.ZeroFreeGlobalAllocUnicode(keyNamePtr);
            Marshal.ZeroFreeGlobalAllocUnicode(passwordPtr);
        }
    }

    static class NativeMethods {
        internal static class NCrypt {
            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern Int32 NCryptExportKey(
                SafeNCryptKeyHandle hKey,
                IntPtr hExportKey,
                String pszBlobType,
                ref nCrypt2.NCryptBufferDesc pParameterList,
                Byte[] pbOutput,
                Int32 cbOutput,
                [Out] out Int32 pcbResult,
                Int32 dwFlags);




            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern Int32 NCryptImportKey(
                SafeNCryptProviderHandle hProvider,
                IntPtr hImportKey,
                String pszBlobType,
                ref nCrypt2.NCryptBufferDesc pParameterList,
                out SafeNCryptKeyHandle phKey,
                IntPtr pbData,
                Int32 cbData,
                NCryptImportFlags dwFlags);
        }
    }
}
