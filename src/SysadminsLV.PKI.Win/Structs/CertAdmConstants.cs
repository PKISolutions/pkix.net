using System;

namespace PKI.Structs {
    class CertAdmConstants {
        #region ICertAdmin2 PropID
        public const Int32 CrPropFileversion                = 0x00000001; // CA File Version
        public const Int32 CrPropProductversion             = 0x00000002; // CA Product Version
        public const Int32 CrPropExitcount                  = 0x00000003; // Exit Count
        public const Int32 CrPropExitdescription            = 0x00000004; // Exit Description
        public const Int32 CrPropPolicydescription          = 0x00000005; // Policy Description
        public const Int32 CrPropCaname                     = 0x00000006; // Certification Authority Name
        public const Int32 CrPropSanitizedcaname            = 0x00000007; // Sanitized CA Name
        public const Int32 CrPropSharedfolder               = 0x00000008; // Shared Folder Path
        public const Int32 CrPropParentca                   = 0x00000009; // Parent CA Name
        public const Int32 CrPropCatype                     = 0x0000000A; // CA Type
        public const Int32 CrPropCasigcertcount             = 0x0000000B; // CA Signature Certificate Count
        public const Int32 CrPropCasigcert                  = 0x0000000C; // CA Signature Certificate
        public const Int32 CrPropCasigcertchain             = 0x0000000D; // CA signing certificate Chain
        public const Int32 CrPropCaxchgcertcount            = 0x0000000E; // CA Exchange Certificate Count
        public const Int32 CrPropCaxchgcert                 = 0x0000000F; // CA Exchange Certificate
        public const Int32 CrPropCaxchgcertchain            = 0x00000010; // CA Exchange Certificate Chain
        public const Int32 CrPropBaseCrl                    = 0x00000011; // Base CRL
        public const Int32 CrPropDeltaCrl                   = 0x00000012; // Delta CRL
        public const Int32 CrPropCacertstate                = 0x00000013; // CA Signing Certificates State
        public const Int32 CrPropCrlstate                   = 0x00000014; // CA CRL State
        public const Int32 CrPropCapropidmax                = 0x00000015; // Maximum Property ID
        public const Int32 CrPropDnsname                    = 0x00000016; // CA Fully Qualified DNS
        public const Int32 CrPropRoleseparationenabled      = 0x00000017; // Role Separated Enabled
        public const Int32 CrPropKracertusedcount           = 0x00000018; // Count Of Required KRAs For Archival
        public const Int32 CrPropKracertcount               = 0x00000019; // Count Of Registered KRAs
        public const Int32 CrPropKracert                    = 0x0000001A; // KRA Certificate
        public const Int32 CrPropKracertstate               = 0x0000001B; // KRA Certificates State
        public const Int32 CrPropAdvancedserver             = 0x0000001C; // Advanced Server
        public const Int32 CrPropTemplates                  = 0x0000001D; // Configured Certificate Templates
        public const Int32 CrPropBasecrlpublishstatus       = 0x0000001E; // Base CRL Publishing Status
        public const Int32 CrPropDeltacrlpublishstatus      = 0x0000001F; // Delta CRL Publishing State
        public const Int32 CrPropCasigcertcrlchain          = 0x00000020; // CA Signing Certificate Chain and CRL
        public const Int32 CrPropCaxchgcertcrlchain         = 0x00000021; // CA Exchange Certificate Chain and CRL
        public const Int32 CrPropCacertstatuscode           = 0x00000022; // CA Signing Certificate Status
        public const Int32 CrPropCaforwardcrosscert         = 0x00000023; // CA Forward Cross Certificate
        public const Int32 CrPropCabackwardcrosscert        = 0x00000024; // CA Backward Cross Certificate
        public const Int32 CrPropCaforwardcrosscertstate    = 0x00000025; // CA Forward Cross Certificate State
        public const Int32 CrPropCabackwardcrosscertstate   = 0x00000026; // CA Backward Cross Certificate State
        public const Int32 CrPropCacertversion              = 0x00000027; // CA Signing Certificates Revisions
        public const Int32 CrPropSanitizedcashortname       = 0x00000028; // CA Sanitized Short Name
        public const Int32 CrPropCertcdpurls                = 0x00000029; // CRL Distribution Points
        public const Int32 CrPropCertaiaurls                = 0x0000002A; // Authority Information Access
        public const Int32 CrPropCertaiaocsprls             = 0x0000002B; // OCSP URLs
        public const Int32 CrPropLocalename                 = 0x0000002C; // CA Locale Name
        public const Int32 CrPropSubjecttemplateOids        = 0x0000002D; // Subject Template
        #endregion

        #region ICertAdmin2 PropType
        public const Int32 ProptypeLong     = 1;
        public const Int32 ProptypeDate     = 2;
        public const Int32 ProptypeBinary   = 3;
        public const Int32 ProptypeString   = 4;
        #endregion

        #region ICertAdmin2 disposition
        public const Int32 CA_DISP_INCOMPLETE       = 0x00000000;
        public const Int32 CA_DISP_ERROR            = 0x00000001;
        public const Int32 CA_DISP_REVOKED          = 0x00000002;
        public const Int32 CA_DISP_VALID            = 0x00000003;
        public const Int32 CA_DISP_INVALID          = 0x00000004;
        public const Int32 CA_DISP_UNDER_SUBMISSION = 0x00000005;
        #endregion

        #region KRA disposition
        public const Int32 KRADispExpired   = 0x00000000; // The certificate has expired
        public const Int32 KRADispNotfound  = 0x00000001; // The certificate was not found
        public const Int32 KRADispRevoked   = 0x00000002; // The certificate has been revoked
        public const Int32 KRADispValid     = 0x00000003; // The certificate is valid
        public const Int32 KRADispNotloaded = 0x00000004; // The certificate is not loaded
        public const Int32 KRADispInvalid   = 0x00000005; // The certificate is invalid
        #endregion

        #region ICertView
        public const Int32 CVRC_COLUMN_SCHEMA = 0;
        public const Int32 CVRC_COLUMN_RESULT = 1;
        public const Int32 CVRC_COLUMN_VALUE  = 2;
        public const Int32 CVRC_COLUMN_MASK   = 0xfff;

        public const Int32 CVR_SORT_NONE    = 0;
        public const Int32 CVR_SORT_ASCEND  = 1;
        public const Int32 CVR_SORT_DESCEND = 2;

        public const Int32 CV_OUT_BASE64HEADER        = 0x0;
        public const Int32 CV_OUT_BASE64              = 0x1;
        public const Int32 CV_OUT_BINARY              = 0x2;
        public const Int32 CV_OUT_BASE64REQUESTHEADER = 0x3;
        public const Int32 CV_OUT_HEX                 = 0x4;
        public const Int32 CV_OUT_HEXASCII            = 0x5;
        public const Int32 CV_OUT_BASE64X509CRLHEADER = 0x9;
        public const Int32 CV_OUT_HEXADDR             = 0xA;
        public const Int32 CV_OUT_HEXASCIIADDR        = 0xB;
        public const Int32 CV_OUT_HEXRAW              = 0xC;
        #endregion
    }
}
