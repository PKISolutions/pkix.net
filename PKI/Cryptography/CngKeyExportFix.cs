using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;
using PKI.Structs;
using SysadminsLV.PKI.Utils.CLRExtensions;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Cryptography {
    public static class CngKeyExportFix {
        const String NCRYPT_PKCS8_PRIVATE_KEY_BLOB = "PKCS8_PRIVATEKEY";
        static readonly Byte[] _pkcs12TripleDesOidBytes = Encoding.ASCII.GetBytes("1.2.840.113549.1.12.1.3\0");

        public static Byte[] ConvertPfx2Pkcs8(Byte[] pfxBytes, String password) {
            const X509KeyStorageFlags flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet;

            var cert = new X509Certificate2(pfxBytes, password, flags);
            try {
                return ConvertCert2Pkcs8(cert);
            } finally {
                cert.DeletePrivateKey();
                cert.Reset();
            }
        }
        public static Byte[] ConvertCert2Pkcs8(X509Certificate2 cert) {
            if (cert == null) {
                throw new ArgumentNullException(nameof(cert));
            }

            Boolean gotKey = Crypt32.CryptAcquireCertificatePrivateKey(
                cert.Handle,
                Wincrypt.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
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
                    using (var cngKey = CngKey.Open(keyHandle, CngKeyHandleOpenOptions.None)) {
                        // If the CNG->CAPI bridge opened the key then AllowPlaintextExport is already set.
                        return (cngKey.ExportPolicy & CngExportPolicies.AllowPlaintextExport) == 0
                            ? fixExportability(cngKey)
                            : cngKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
                    }
                }

                return null;
            }
        }

        static Byte[] fixExportability(CngKey cngKey) {
            const String password = "1";
            Byte[] encryptedPkcs8 = exportEncryptedPkcs8(cngKey, password, 1);

            using (cngKey.ProviderHandle) {
                return importEncryptedPkcs8Overwrite(encryptedPkcs8, cngKey, password);
            }
        }
        static Byte[] exportEncryptedPkcs8(
            CngKey cngKey,
            String password,
            Int32 kdfCount) {
            IntPtr buffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(nCrypt2.BCryptBuffer)) * 3);
            
            
            IntPtr next = buffers;
            IntPtr passwordPtr = Marshal.StringToHGlobalUni(password);
            var buff = new nCrypt2.BCryptBuffer {
                BufferType = BCryptBufferType.PkcsSecret,
                cbBuffer = 2 * (password.Length + 1),
                pvBuffer = passwordPtr
            };
            if (IntPtr.Zero.Equals(buff.pvBuffer)) {
                buff.cbBuffer = 0;
            }
            Marshal.StructureToPtr(buff, next, false);

            IntPtr oidPtr = Marshal.AllocHGlobal(_pkcs12TripleDesOidBytes.Length);
            Marshal.Copy(_pkcs12TripleDesOidBytes, 0, oidPtr, _pkcs12TripleDesOidBytes.Length);
            buff = new nCrypt2.BCryptBuffer {
                BufferType = BCryptBufferType.PkcsAlgOid,
                cbBuffer = _pkcs12TripleDesOidBytes.Length,
                pvBuffer = oidPtr
            };
            next += Marshal.SizeOf(typeof(nCrypt2.BCryptBuffer));
            Marshal.StructureToPtr(buff, next, false);

            // copy PBE params
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
            IntPtr pbeParamsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(pbeParams));
            Marshal.StructureToPtr(pbeParams, pbeParamsPtr, false);
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


            using (SafeNCryptKeyHandle keyHandle = cngKey.Handle) {
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
                Marshal.FreeHGlobal(oidPtr);

                return exported;
            }
        }

        static Byte[] importEncryptedPkcs8Overwrite(
            Byte[] encryptedPkcs8,
            CngKey cngKey,
            String password) {
            // copy key name to unmanaged memory
            IntPtr keyNamePtr = Marshal.StringToHGlobalUni(cngKey.KeyName);
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
                cbBuffer = 2 * (cngKey.KeyName.Length + 1),
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
            IntPtr descPtr = Marshal.AllocHGlobal(Marshal.SizeOf(desc));
            Marshal.StructureToPtr(desc, descPtr, false);

            NCryptImportFlags flags =
                NCryptImportFlags.NCRYPT_OVERWRITE_KEY_FLAG |
                NCryptImportFlags.NCRYPT_DO_NOT_FINALIZE_FLAG;

            if (cngKey.IsMachineKey) {
                flags |= NCryptImportFlags.NCRYPT_MACHINE_KEY_FLAG;
            }

            Int32 errorCode = NCrypt.NCryptImportKey(
                cngKey.ProviderHandle,
                IntPtr.Zero,
                NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                descPtr,
                out SafeNCryptKeyHandle keyHandle,
                encryptedPkcs8,
                encryptedPkcs8.Length,
                flags);

            Marshal.FreeHGlobal(buffers);
            Marshal.ZeroFreeGlobalAllocUnicode(keyNamePtr);
            Marshal.ZeroFreeGlobalAllocUnicode(passwordPtr);

            if (errorCode != 0) {
                keyHandle.Dispose();
                throw new Win32Exception(errorCode);
            }

            using (keyHandle) {
                using (var importedKey = CngKey.Open(keyHandle, CngKeyHandleOpenOptions.None)) {
                    const CngExportPolicies desiredPolicies =
                        CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport;

                    importedKey.SetProperty(
                        new CngProperty(
                            "Export Policy",
                            BitConverter.GetBytes((Int32)desiredPolicies),
                            CngPropertyOptions.Persist));

                    Int32 error = NCrypt.NCryptFinalizeKey(keyHandle, 0);

                    if (error != 0) {
                        throw new Win32Exception(error);
                    }
                }

                using (var c = CngKey.Open(keyHandle, CngKeyHandleOpenOptions.None)) {
                    return c.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
                }
            }
        }
    }
}
