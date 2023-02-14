using System;
using System.Runtime.InteropServices;

namespace PKI.Structs;

/// <summary>
/// <strong>nCrypt</strong> class represents a set of unmanaged structures that are translated to .NET Framework compatible
/// structures.
/// <p>This class do not provide any constructors and static methods.</p>
/// </summary>
/// <remarks>Most of these structures are related to <strong>CryptoAPI</strong> and are defined in <strong>ncrypt.h</strong>
/// header file.</remarks>
static class nCrypt2 {
    #region enums
    public const UInt32 NCRYPT_CIPHER_OPERATION                = 0x00000001;
    public const UInt32 NCRYPT_HASH_OPERATION                  = 0x00000002;
    public const UInt32 NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 0x00000004;
    public const UInt32 NCRYPT_SECRET_AGREEMENT_OPERATION      = 0x00000008;
    public const UInt32 NCRYPT_SIGNATURE_OPERATION             = 0x00000010;
    public const Int32 NCRYPT_MACHINE_KEY_FLAG                 = 0x00000020;

    // Key Storage Property Identifiers
    public const String NCRYPT_NAME_PROPERTY                   = "Name";
    public const String NCRYPT_UNIQUE_NAME_PROPERTY            = "Unique Name";
    public const String NCRYPT_ALGORITHM_PROPERTY              = "Algorithm Name";
    public const String NCRYPT_LENGTH_PROPERTY                 = "Length";
    public const String NCRYPT_LENGTHS_PROPERTY                = "Lengths";
    public const String NCRYPT_BLOCK_LENGTH_PROPERTY           = "Block Length";
    public const String NCRYPT_UI_POLICY_PROPERTY              = "UI Policy";
    public const String NCRYPT_EXPORT_POLICY_PROPERTY          = "Export Policy";
    public const String NCRYPT_WINDOW_HANDLE_PROPERTY          = "HWND Handle";
    public const String NCRYPT_USE_CONTEXT_PROPERTY            = "Use Context";
    public const String NCRYPT_IMPL_TYPE_PROPERTY              = "Impl Type";
    public const String NCRYPT_KEY_USAGE_PROPERTY              = "Key Usage";
    public const String NCRYPT_KEY_TYPE_PROPERTY               = "Key Type";
    public const String NCRYPT_VERSION_PROPERTY                = "Version";
    public const String NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY = "Security Descr Support";
    public const String NCRYPT_SECURITY_DESCR_PROPERTY         = "Security Descr";
    public const String NCRYPT_USE_COUNT_ENABLED_PROPERTY      = "Enabled Use Count";
    public const String NCRYPT_USE_COUNT_PROPERTY              = "Use Count";
    public const String NCRYPT_LAST_MODIFIED_PROPERTY          = "Modified";
    public const String NCRYPT_MAX_NAME_LENGTH_PROPERTY        = "Max Name Length";
    public const String NCRYPT_ALGORITHM_GROUP_PROPERTY        = "Algorithm Group";
    public const String NCRYPT_DH_PARAMETERS_PROPERTY          = "DHParameters";
    public const String NCRYPT_PROVIDER_HANDLE_PROPERTY        = "Provider Handle";
    public const String NCRYPT_PIN_PROPERTY                    = "SmartCardPin";
    public const String NCRYPT_READER_PROPERTY                 = "SmartCardReader";
    public const String NCRYPT_SMARTCARD_GUID_PROPERTY         = "SmartCardGuid";
    public const String NCRYPT_CERTIFICATE_PROPERTY            = "SmartCardKeyCertificate";
    public const String NCRYPT_PIN_PROMPT_PROPERTY             = "SmartCardPinPrompt";
    public const String NCRYPT_USER_CERTSTORE_PROPERTY         = "SmartCardUserCertStore";
    public const String NCRYPT_ROOT_CERTSTORE_PROPERTY         = "SmartcardRootCertStore";
    public const String NCRYPT_SECURE_PIN_PROPERTY             = "SmartCardSecurePin";
    public const String NCRYPT_ASSOCIATED_ECDH_KEY             = "SmartCardAssociatedECDHKey";
    public const String NCRYPT_SCARD_PIN_ID                    = "SmartCardPinId";
    public const String NCRYPT_SCARD_PIN_INFO                  = "SmartCardPinInfo";
    #endregion

    [StructLayout(LayoutKind.Sequential)]
    public struct BCRYPT_PKCS1_PADDING_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]
        public String pszAlgId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BCRYPT_PSS_PADDING_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]
        public String pszAlgId;
        public Int32 cbSalt;
    }

}