
//  Microsoft (R) .NET Framework IL Disassembler.  Version 4.8.3928.0
//  Copyright (c) Microsoft Corporation.  All rights reserved.



// Metadata version: v4.0.30319
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly CERTADMINLib
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 35 44 45 39 39 41 30 2D 37 46 42 36   // ..$35DE99A0-7FB6
                                                                                                  2D 31 31 44 30 2D 38 38 31 37 2D 30 30 41 30 43   // -11D0-8817-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ImportedFromTypeLibAttribute::.ctor(string) = ( 01 00 0C 43 45 52 54 41 44 4D 49 4E 4C 69 62 00   // ...CERTADMINLib.
                                                                                                                 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibVersionAttribute::.ctor(int32,
                                                                                                int32) = ( 01 00 01 00 00 00 00 00 00 00 00 00 ) 
  .hash algorithm 0x00008004
  .ver 1:0:0:0
}
.module CERTADMINLib.dll
// MVID: {39A2F386-276D-4F49-ACEF-C187EE3AE8C7}
.imagebase 0x00400000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00000001    //  ILONLY
// Image base: 0x06B30000


// =============== CLASS MEMBERS DECLARATION ===================

.class interface public abstract auto ansi import CERTADMINLib.ICertAdmin
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 34 44 46 36 39 35 30 2D 37 46 42 36   // ..$34DF6950-7FB6
                                                                                                  2D 31 31 44 30 2D 38 38 31 37 2D 30 30 41 30 43   // -11D0-8817-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .method public hidebysig newslot abstract virtual 
          instance int32  IsValidCertificate([in] string  marshal( bstr) strConfig,
                                             [in] string  marshal( bstr) strSerialNumber) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin::IsValidCertificate

  .method public hidebysig newslot abstract virtual 
          instance int32  GetRevocationReason() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin::GetRevocationReason

  .method public hidebysig newslot abstract virtual 
          instance void  RevokeCertificate([in] string  marshal( bstr) strConfig,
                                           [in] string  marshal( bstr) strSerialNumber,
                                           [in] int32 Reason,
                                           [in] valuetype [mscorlib]System.DateTime Date) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin::RevokeCertificate

  .method public hidebysig newslot abstract virtual 
          instance void  SetRequestAttributes([in] string  marshal( bstr) strConfig,
                                              [in] int32 RequestId,
                                              [in] string  marshal( bstr) strAttributes) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin::SetRequestAttributes

  .method public hidebysig newslot abstract virtual 
          instance void  SetCertificateExtension([in] string  marshal( bstr) strConfig,
                                                 [in] int32 RequestId,
                                                 [in] string  marshal( bstr) strExtensionName,
                                                 [in] int32 Type,
                                                 [in] int32 Flags,
                                                 [in] native int pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin::SetCertificateExtension

  .method public hidebysig newslot abstract virtual 
          instance void  DenyRequest([in] string  marshal( bstr) strConfig,
                                     [in] int32 RequestId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin::DenyRequest

  .method public hidebysig newslot abstract virtual 
          instance int32  ResubmitRequest([in] string  marshal( bstr) strConfig,
                                          [in] int32 RequestId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin::ResubmitRequest

  .method public hidebysig newslot abstract virtual 
          instance void  PublishCRL([in] string  marshal( bstr) strConfig,
                                    [in] valuetype [mscorlib]System.DateTime Date) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin::PublishCRL

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCRL([in] string  marshal( bstr) strConfig,
                 [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin::GetCRL

  .method public hidebysig newslot abstract virtual 
          instance int32  ImportCertificate([in] string  marshal( bstr) strConfig,
                                            [in] string  marshal( bstr) strCertificate,
                                            [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin::ImportCertificate

} // end of class CERTADMINLib.ICertAdmin

.class interface public abstract auto ansi import CERTADMINLib.ICertAdmin2
       implements CERTADMINLib.ICertAdmin
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 46 37 43 33 41 43 34 31 2D 42 38 43 45   // ..$F7C3AC41-B8CE
                                                                                                  2D 34 46 42 34 2D 41 41 35 38 2D 33 44 31 44 43   // -4FB4-AA58-3D1DC
                                                                                                  30 45 33 36 42 33 39 00 00 )                      // 0E36B39..
  .method public hidebysig newslot abstract virtual 
          instance int32  IsValidCertificate([in] string  marshal( bstr) strConfig,
                                             [in] string  marshal( bstr) strSerialNumber) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::IsValidCertificate

  .method public hidebysig newslot abstract virtual 
          instance int32  GetRevocationReason() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::GetRevocationReason

  .method public hidebysig newslot abstract virtual 
          instance void  RevokeCertificate([in] string  marshal( bstr) strConfig,
                                           [in] string  marshal( bstr) strSerialNumber,
                                           [in] int32 Reason,
                                           [in] valuetype [mscorlib]System.DateTime Date) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::RevokeCertificate

  .method public hidebysig newslot abstract virtual 
          instance void  SetRequestAttributes([in] string  marshal( bstr) strConfig,
                                              [in] int32 RequestId,
                                              [in] string  marshal( bstr) strAttributes) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::SetRequestAttributes

  .method public hidebysig newslot abstract virtual 
          instance void  SetCertificateExtension([in] string  marshal( bstr) strConfig,
                                                 [in] int32 RequestId,
                                                 [in] string  marshal( bstr) strExtensionName,
                                                 [in] int32 Type,
                                                 [in] int32 Flags,
                                                 [in] native int pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::SetCertificateExtension

  .method public hidebysig newslot abstract virtual 
          instance void  DenyRequest([in] string  marshal( bstr) strConfig,
                                     [in] int32 RequestId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::DenyRequest

  .method public hidebysig newslot abstract virtual 
          instance int32  ResubmitRequest([in] string  marshal( bstr) strConfig,
                                          [in] int32 RequestId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::ResubmitRequest

  .method public hidebysig newslot abstract virtual 
          instance void  PublishCRL([in] string  marshal( bstr) strConfig,
                                    [in] valuetype [mscorlib]System.DateTime Date) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::PublishCRL

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCRL([in] string  marshal( bstr) strConfig,
                 [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::GetCRL

  .method public hidebysig newslot abstract virtual 
          instance int32  ImportCertificate([in] string  marshal( bstr) strConfig,
                                            [in] string  marshal( bstr) strCertificate,
                                            [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 02 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::ImportCertificate

  .method public hidebysig newslot abstract virtual 
          instance void  PublishCRLs([in] string  marshal( bstr) strConfig,
                                     [in] valuetype [mscorlib]System.DateTime Date,
                                     [in] int32 CRLFlags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::PublishCRLs

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetCAProperty([in] string  marshal( bstr) strConfig,
                        [in] int32 PropId,
                        [in] int32 PropIndex,
                        [in] int32 PropType,
                        [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::GetCAProperty

  .method public hidebysig newslot abstract virtual 
          instance void  SetCAProperty([in] string  marshal( bstr) strConfig,
                                       [in] int32 PropId,
                                       [in] int32 PropIndex,
                                       [in] int32 PropType,
                                       [in] object&  marshal( struct) pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::SetCAProperty

  .method public hidebysig newslot abstract virtual 
          instance int32  GetCAPropertyFlags([in] string  marshal( bstr) strConfig,
                                             [in] int32 PropId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::GetCAPropertyFlags

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCAPropertyDisplayName([in] string  marshal( bstr) strConfig,
                                   [in] int32 PropId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::GetCAPropertyDisplayName

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetArchivedKey([in] string  marshal( bstr) strConfig,
                         [in] int32 RequestId,
                         [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::GetArchivedKey

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetConfigEntry([in] string  marshal( bstr) strConfig,
                         [in] string  marshal( bstr) strNodePath,
                         [in] string  marshal( bstr) strEntryName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::GetConfigEntry

  .method public hidebysig newslot abstract virtual 
          instance void  SetConfigEntry([in] string  marshal( bstr) strConfig,
                                        [in] string  marshal( bstr) strNodePath,
                                        [in] string  marshal( bstr) strEntryName,
                                        [in] object&  marshal( struct) pvarEntry) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::SetConfigEntry

  .method public hidebysig newslot abstract virtual 
          instance void  ImportKey([in] string  marshal( bstr) strConfig,
                                   [in] int32 RequestId,
                                   [in] string  marshal( bstr) strCertHash,
                                   [in] int32 Flags,
                                   [in] string  marshal( bstr) strKey) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::ImportKey

  .method public hidebysig newslot abstract virtual 
          instance int32  GetMyRoles([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::GetMyRoles

  .method public hidebysig newslot abstract virtual 
          instance int32  DeleteRow([in] string  marshal( bstr) strConfig,
                                    [in] int32 Flags,
                                    [in] valuetype [mscorlib]System.DateTime Date,
                                    [in] int32 Table,
                                    [in] int32 RowId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 03 60 00 00 )                         // .....`..
  } // end of method ICertAdmin2::DeleteRow

} // end of class CERTADMINLib.ICertAdmin2

.class interface public abstract auto ansi import CERTADMINLib.CCertAdmin
       implements CERTADMINLib.ICertAdmin2
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 1C 43 45 52 54 41 44 4D 49 4E 4C 69 62 2E   // ...CERTADMINLib.
                                                                                                                          43 43 65 72 74 41 64 6D 69 6E 43 6C 61 73 73 00   // CCertAdminClass.
                                                                                                                          00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 46 37 43 33 41 43 34 31 2D 42 38 43 45   // ..$F7C3AC41-B8CE
                                                                                                  2D 34 46 42 34 2D 41 41 35 38 2D 33 44 31 44 43   // -4FB4-AA58-3D1DC
                                                                                                  30 45 33 36 42 33 39 00 00 )                      // 0E36B39..
} // end of class CERTADMINLib.CCertAdmin

.class public auto ansi import CERTADMINLib.CCertAdminClass
       extends [mscorlib]System.Object
       implements CERTADMINLib.ICertAdmin2,
                  CERTADMINLib.CCertAdmin
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 37 45 41 42 41 46 30 2D 37 46 42 36   // ..$37EABAF0-7FB6
                                                                                                  2D 31 31 44 30 2D 38 38 31 37 2D 30 30 41 30 43   // -11D0-8817-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertAdminClass::.ctor

  .method public hidebysig newslot virtual 
          instance int32  IsValidCertificate([in] string  marshal( bstr) strConfig,
                                             [in] string  marshal( bstr) strSerialNumber) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::IsValidCertificate
  } // end of method CCertAdminClass::IsValidCertificate

  .method public hidebysig newslot virtual 
          instance int32  GetRevocationReason() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::GetRevocationReason
  } // end of method CCertAdminClass::GetRevocationReason

  .method public hidebysig newslot virtual 
          instance void  RevokeCertificate([in] string  marshal( bstr) strConfig,
                                           [in] string  marshal( bstr) strSerialNumber,
                                           [in] int32 Reason,
                                           [in] valuetype [mscorlib]System.DateTime Date) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::RevokeCertificate
  } // end of method CCertAdminClass::RevokeCertificate

  .method public hidebysig newslot virtual 
          instance void  SetRequestAttributes([in] string  marshal( bstr) strConfig,
                                              [in] int32 RequestId,
                                              [in] string  marshal( bstr) strAttributes) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::SetRequestAttributes
  } // end of method CCertAdminClass::SetRequestAttributes

  .method public hidebysig newslot virtual 
          instance void  SetCertificateExtension([in] string  marshal( bstr) strConfig,
                                                 [in] int32 RequestId,
                                                 [in] string  marshal( bstr) strExtensionName,
                                                 [in] int32 Type,
                                                 [in] int32 Flags,
                                                 [in] native int pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::SetCertificateExtension
  } // end of method CCertAdminClass::SetCertificateExtension

  .method public hidebysig newslot virtual 
          instance void  DenyRequest([in] string  marshal( bstr) strConfig,
                                     [in] int32 RequestId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::DenyRequest
  } // end of method CCertAdminClass::DenyRequest

  .method public hidebysig newslot virtual 
          instance int32  ResubmitRequest([in] string  marshal( bstr) strConfig,
                                          [in] int32 RequestId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::ResubmitRequest
  } // end of method CCertAdminClass::ResubmitRequest

  .method public hidebysig newslot virtual 
          instance void  PublishCRL([in] string  marshal( bstr) strConfig,
                                    [in] valuetype [mscorlib]System.DateTime Date) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::PublishCRL
  } // end of method CCertAdminClass::PublishCRL

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetCRL([in] string  marshal( bstr) strConfig,
                 [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::GetCRL
  } // end of method CCertAdminClass::GetCRL

  .method public hidebysig newslot virtual 
          instance int32  ImportCertificate([in] string  marshal( bstr) strConfig,
                                            [in] string  marshal( bstr) strCertificate,
                                            [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::ImportCertificate
  } // end of method CCertAdminClass::ImportCertificate

  .method public hidebysig newslot virtual 
          instance void  PublishCRLs([in] string  marshal( bstr) strConfig,
                                     [in] valuetype [mscorlib]System.DateTime Date,
                                     [in] int32 CRLFlags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::PublishCRLs
  } // end of method CCertAdminClass::PublishCRLs

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetCAProperty([in] string  marshal( bstr) strConfig,
                        [in] int32 PropId,
                        [in] int32 PropIndex,
                        [in] int32 PropType,
                        [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::GetCAProperty
  } // end of method CCertAdminClass::GetCAProperty

  .method public hidebysig newslot virtual 
          instance void  SetCAProperty([in] string  marshal( bstr) strConfig,
                                       [in] int32 PropId,
                                       [in] int32 PropIndex,
                                       [in] int32 PropType,
                                       [in] object&  marshal( struct) pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::SetCAProperty
  } // end of method CCertAdminClass::SetCAProperty

  .method public hidebysig newslot virtual 
          instance int32  GetCAPropertyFlags([in] string  marshal( bstr) strConfig,
                                             [in] int32 PropId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::GetCAPropertyFlags
  } // end of method CCertAdminClass::GetCAPropertyFlags

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetCAPropertyDisplayName([in] string  marshal( bstr) strConfig,
                                   [in] int32 PropId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::GetCAPropertyDisplayName
  } // end of method CCertAdminClass::GetCAPropertyDisplayName

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetArchivedKey([in] string  marshal( bstr) strConfig,
                         [in] int32 RequestId,
                         [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::GetArchivedKey
  } // end of method CCertAdminClass::GetArchivedKey

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetConfigEntry([in] string  marshal( bstr) strConfig,
                         [in] string  marshal( bstr) strNodePath,
                         [in] string  marshal( bstr) strEntryName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::GetConfigEntry
  } // end of method CCertAdminClass::GetConfigEntry

  .method public hidebysig newslot virtual 
          instance void  SetConfigEntry([in] string  marshal( bstr) strConfig,
                                        [in] string  marshal( bstr) strNodePath,
                                        [in] string  marshal( bstr) strEntryName,
                                        [in] object&  marshal( struct) pvarEntry) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::SetConfigEntry
  } // end of method CCertAdminClass::SetConfigEntry

  .method public hidebysig newslot virtual 
          instance void  ImportKey([in] string  marshal( bstr) strConfig,
                                   [in] int32 RequestId,
                                   [in] string  marshal( bstr) strCertHash,
                                   [in] int32 Flags,
                                   [in] string  marshal( bstr) strKey) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::ImportKey
  } // end of method CCertAdminClass::ImportKey

  .method public hidebysig newslot virtual 
          instance int32  GetMyRoles([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::GetMyRoles
  } // end of method CCertAdminClass::GetMyRoles

  .method public hidebysig newslot virtual 
          instance int32  DeleteRow([in] string  marshal( bstr) strConfig,
                                    [in] int32 Flags,
                                    [in] valuetype [mscorlib]System.DateTime Date,
                                    [in] int32 Table,
                                    [in] int32 RowId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertAdmin2::DeleteRow
  } // end of method CCertAdminClass::DeleteRow

} // end of class CERTADMINLib.CCertAdminClass

.class interface public abstract auto ansi import CERTADMINLib.ICertView
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 43 33 46 41 43 33 34 34 2D 31 45 38 34   // ..$C3FAC344-1E84
                                                                                                  2D 31 31 44 31 2D 39 42 44 36 2D 30 30 43 30 34   // -11D1-9BD6-00C04
                                                                                                  46 42 36 38 33 46 41 00 00 )                      // FB683FA..
  .method public hidebysig newslot abstract virtual 
          instance void  OpenConnection([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView::OpenConnection

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWCOLUMN 
          marshal( interface ) 
          EnumCertViewColumn([in] int32 fResultColumn) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView::EnumCertViewColumn

  .method public hidebysig newslot abstract virtual 
          instance int32  GetColumnCount([in] int32 fResultColumn) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView::GetColumnCount

  .method public hidebysig newslot abstract virtual 
          instance int32  GetColumnIndex([in] int32 fResultColumn,
                                         [in] string  marshal( bstr) strColumnName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView::GetColumnIndex

  .method public hidebysig newslot abstract virtual 
          instance void  SetResultColumnCount([in] int32 cResultColumn) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView::SetResultColumnCount

  .method public hidebysig newslot abstract virtual 
          instance void  SetResultColumn([in] int32 ColumnIndex) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView::SetResultColumn

  .method public hidebysig newslot abstract virtual 
          instance void  SetRestriction([in] int32 ColumnIndex,
                                        [in] int32 SeekOperator,
                                        [in] int32 SortOrder,
                                        [in] object&  marshal( struct) pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView::SetRestriction

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWROW 
          marshal( interface ) 
          OpenView() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView::OpenView

} // end of class CERTADMINLib.ICertView

.class interface public abstract auto ansi import CERTADMINLib.ICertView2
       implements CERTADMINLib.ICertView
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 44 35 39 34 42 32 38 32 2D 38 38 35 31   // ..$D594B282-8851
                                                                                                  2D 34 42 36 31 2D 39 43 36 36 2D 33 45 44 41 44   // -4B61-9C66-3EDAD
                                                                                                  46 38 34 38 38 36 33 00 00 )                      // F848863..
  .method public hidebysig newslot abstract virtual 
          instance void  OpenConnection([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView2::OpenConnection

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWCOLUMN 
          marshal( interface ) 
          EnumCertViewColumn([in] int32 fResultColumn) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView2::EnumCertViewColumn

  .method public hidebysig newslot abstract virtual 
          instance int32  GetColumnCount([in] int32 fResultColumn) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView2::GetColumnCount

  .method public hidebysig newslot abstract virtual 
          instance int32  GetColumnIndex([in] int32 fResultColumn,
                                         [in] string  marshal( bstr) strColumnName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView2::GetColumnIndex

  .method public hidebysig newslot abstract virtual 
          instance void  SetResultColumnCount([in] int32 cResultColumn) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView2::SetResultColumnCount

  .method public hidebysig newslot abstract virtual 
          instance void  SetResultColumn([in] int32 ColumnIndex) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView2::SetResultColumn

  .method public hidebysig newslot abstract virtual 
          instance void  SetRestriction([in] int32 ColumnIndex,
                                        [in] int32 SeekOperator,
                                        [in] int32 SortOrder,
                                        [in] object&  marshal( struct) pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView2::SetRestriction

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWROW 
          marshal( interface ) 
          OpenView() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
  } // end of method ICertView2::OpenView

  .method public hidebysig newslot abstract virtual 
          instance void  SetTable([in] int32 Table) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
  } // end of method ICertView2::SetTable

} // end of class CERTADMINLib.ICertView2

.class interface public abstract auto ansi import CERTADMINLib.CCertView
       implements CERTADMINLib.ICertView2
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 1B 43 45 52 54 41 44 4D 49 4E 4C 69 62 2E   // ...CERTADMINLib.
                                                                                                                          43 43 65 72 74 56 69 65 77 43 6C 61 73 73 00 00 ) // CCertViewClass..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 44 35 39 34 42 32 38 32 2D 38 38 35 31   // ..$D594B282-8851
                                                                                                  2D 34 42 36 31 2D 39 43 36 36 2D 33 45 44 41 44   // -4B61-9C66-3EDAD
                                                                                                  46 38 34 38 38 36 33 00 00 )                      // F848863..
} // end of class CERTADMINLib.CCertView

.class public auto ansi import CERTADMINLib.CCertViewClass
       extends [mscorlib]System.Object
       implements CERTADMINLib.ICertView2,
                  CERTADMINLib.CCertView
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 41 31 32 44 30 46 37 41 2D 31 45 38 34   // ..$A12D0F7A-1E84
                                                                                                  2D 31 31 44 31 2D 39 42 44 36 2D 30 30 43 30 34   // -11D1-9BD6-00C04
                                                                                                  46 42 36 38 33 46 41 00 00 )                      // FB683FA..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertViewClass::.ctor

  .method public hidebysig newslot virtual 
          instance void  OpenConnection([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertView2::OpenConnection
  } // end of method CCertViewClass::OpenConnection

  .method public hidebysig newslot virtual 
          instance class CERTADMINLib.IEnumCERTVIEWCOLUMN 
          marshal( interface ) 
          EnumCertViewColumn([in] int32 fResultColumn) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertView2::EnumCertViewColumn
  } // end of method CCertViewClass::EnumCertViewColumn

  .method public hidebysig newslot virtual 
          instance int32  GetColumnCount([in] int32 fResultColumn) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertView2::GetColumnCount
  } // end of method CCertViewClass::GetColumnCount

  .method public hidebysig newslot virtual 
          instance int32  GetColumnIndex([in] int32 fResultColumn,
                                         [in] string  marshal( bstr) strColumnName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertView2::GetColumnIndex
  } // end of method CCertViewClass::GetColumnIndex

  .method public hidebysig newslot virtual 
          instance void  SetResultColumnCount([in] int32 cResultColumn) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertView2::SetResultColumnCount
  } // end of method CCertViewClass::SetResultColumnCount

  .method public hidebysig newslot virtual 
          instance void  SetResultColumn([in] int32 ColumnIndex) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertView2::SetResultColumn
  } // end of method CCertViewClass::SetResultColumn

  .method public hidebysig newslot virtual 
          instance void  SetRestriction([in] int32 ColumnIndex,
                                        [in] int32 SeekOperator,
                                        [in] int32 SortOrder,
                                        [in] object&  marshal( struct) pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertView2::SetRestriction
  } // end of method CCertViewClass::SetRestriction

  .method public hidebysig newslot virtual 
          instance class CERTADMINLib.IEnumCERTVIEWROW 
          marshal( interface ) 
          OpenView() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertView2::OpenView
  } // end of method CCertViewClass::OpenView

  .method public hidebysig newslot virtual 
          instance void  SetTable([in] int32 Table) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
    .override CERTADMINLib.ICertView2::SetTable
  } // end of method CCertViewClass::SetTable

} // end of class CERTADMINLib.CCertViewClass

.class interface public abstract auto ansi import CERTADMINLib.IOCSPPropertyCollection
       implements [mscorlib]System.Collections.IEnumerable
{
  .custom instance void [mscorlib]System.Reflection.DefaultMemberAttribute::.ctor(string) = ( 01 00 04 49 74 65 6D 00 00 )                      // ...Item..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 C0 10 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 32 35 39 37 43 31 38 44 2D 35 34 45 36   // ..$2597C18D-54E6
                                                                                                  2D 34 42 37 34 2D 39 46 41 39 2D 41 36 42 46 44   // -4B74-9FA9-A6BFD
                                                                                                  41 39 39 43 42 42 45 00 00 )                      // A99CBBE..
  .method public hidebysig newslot abstract virtual 
          instance class [mscorlib]System.Collections.IEnumerator 
          marshal( custom ("System.Runtime.InteropServices.CustomMarshalers.EnumeratorToEnumVariantMarshaler, CustomMarshalers, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a","")) 
          GetEnumerator() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 FC FF FF FF 00 00 ) 
  } // end of method IOCSPPropertyCollection::GetEnumerator

  .method public hidebysig newslot specialname abstract virtual 
          instance object 
          marshal( struct) 
          get_Item([in] int32 Index) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 00 00 00 00 ) 
  } // end of method IOCSPPropertyCollection::get_Item

  .method public hidebysig newslot specialname abstract virtual 
          instance int32  get_Count() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
  } // end of method IOCSPPropertyCollection::get_Count

  .method public hidebysig newslot specialname abstract virtual 
          instance object 
          marshal( struct) 
          get_ItemByName([in] string  marshal( bstr) bstrPropName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
  } // end of method IOCSPPropertyCollection::get_ItemByName

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IOCSPProperty 
          marshal( interface ) 
          CreateProperty([in] string  marshal( bstr) bstrPropName,
                         [in] object&  marshal( struct) pVarPropValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 00 00 00 00 ) 
  } // end of method IOCSPPropertyCollection::CreateProperty

  .method public hidebysig newslot abstract virtual 
          instance void  DeleteProperty([in] string  marshal( bstr) bstrPropName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 00 00 00 00 ) 
  } // end of method IOCSPPropertyCollection::DeleteProperty

  .method public hidebysig newslot abstract virtual 
          instance void  InitializeFromProperties([in] object&  marshal( struct) pVarProperties) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 00 00 00 00 ) 
  } // end of method IOCSPPropertyCollection::InitializeFromProperties

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetAllProperties() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 00 00 00 00 ) 
  } // end of method IOCSPPropertyCollection::GetAllProperties

  .property object Item(int32)
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 00 00 00 00 ) 
    .get instance object CERTADMINLib.IOCSPPropertyCollection::get_Item(int32)
  } // end of property IOCSPPropertyCollection::Item
  .property int32 Count()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
    .get instance int32 CERTADMINLib.IOCSPPropertyCollection::get_Count()
  } // end of property IOCSPPropertyCollection::Count
  .property object ItemByName(string)
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
    .get instance object CERTADMINLib.IOCSPPropertyCollection::get_ItemByName(string)
  } // end of property IOCSPPropertyCollection::ItemByName
} // end of class CERTADMINLib.IOCSPPropertyCollection

.class interface public abstract auto ansi import CERTADMINLib.OCSPPropertyCollection
       implements CERTADMINLib.IOCSPPropertyCollection
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 32 35 39 37 43 31 38 44 2D 35 34 45 36   // ..$2597C18D-54E6
                                                                                                  2D 34 42 37 34 2D 39 46 41 39 2D 41 36 42 46 44   // -4B74-9FA9-A6BFD
                                                                                                  41 39 39 43 42 42 45 00 00 )                      // A99CBBE..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 28 43 45 52 54 41 44 4D 49 4E 4C 69 62 2E   // ..(CERTADMINLib.
                                                                                                                          4F 43 53 50 50 72 6F 70 65 72 74 79 43 6F 6C 6C   // OCSPPropertyColl
                                                                                                                          65 63 74 69 6F 6E 43 6C 61 73 73 00 00 )          // ectionClass..
} // end of class CERTADMINLib.OCSPPropertyCollection

.class public auto ansi import CERTADMINLib.OCSPPropertyCollectionClass
       extends [mscorlib]System.Object
       implements CERTADMINLib.IOCSPPropertyCollection,
                  CERTADMINLib.OCSPPropertyCollection,
                  [mscorlib]System.Collections.IEnumerable
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 46 39 33 35 41 35 32 38 2D 42 41 38 41   // ..$F935A528-BA8A
                                                                                                  2D 34 44 44 39 2D 42 41 37 39 2D 46 32 38 33 32   // -4DD9-BA79-F2832
                                                                                                  37 35 43 42 32 44 45 00 00 )                      // 75CB2DE..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.DefaultMemberAttribute::.ctor(string) = ( 01 00 04 49 74 65 6D 00 00 )                      // ...Item..
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method OCSPPropertyCollectionClass::.ctor

  .method public hidebysig newslot virtual 
          instance class [mscorlib]System.Collections.IEnumerator 
          marshal( custom ("System.Runtime.InteropServices.CustomMarshalers.EnumeratorToEnumVariantMarshaler, CustomMarshalers, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a","")) 
          GetEnumerator() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 FC FF FF FF 00 00 ) 
    .override CERTADMINLib.IOCSPPropertyCollection::GetEnumerator
  } // end of method OCSPPropertyCollectionClass::GetEnumerator

  .method public hidebysig newslot specialname virtual 
          instance object 
          marshal( struct) 
          get_Item([in] int32 Index) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPPropertyCollection::get_Item
  } // end of method OCSPPropertyCollectionClass::get_Item

  .method public hidebysig newslot specialname virtual 
          instance int32  get_Count() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPPropertyCollection::get_Count
  } // end of method OCSPPropertyCollectionClass::get_Count

  .method public hidebysig newslot specialname virtual 
          instance object 
          marshal( struct) 
          get_ItemByName([in] string  marshal( bstr) bstrPropName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPPropertyCollection::get_ItemByName
  } // end of method OCSPPropertyCollectionClass::get_ItemByName

  .method public hidebysig newslot virtual 
          instance class CERTADMINLib.IOCSPProperty 
          marshal( interface ) 
          CreateProperty([in] string  marshal( bstr) bstrPropName,
                         [in] object&  marshal( struct) pVarPropValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPPropertyCollection::CreateProperty
  } // end of method OCSPPropertyCollectionClass::CreateProperty

  .method public hidebysig newslot virtual 
          instance void  DeleteProperty([in] string  marshal( bstr) bstrPropName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPPropertyCollection::DeleteProperty
  } // end of method OCSPPropertyCollectionClass::DeleteProperty

  .method public hidebysig newslot virtual 
          instance void  InitializeFromProperties([in] object&  marshal( struct) pVarProperties) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPPropertyCollection::InitializeFromProperties
  } // end of method OCSPPropertyCollectionClass::InitializeFromProperties

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetAllProperties() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPPropertyCollection::GetAllProperties
  } // end of method OCSPPropertyCollectionClass::GetAllProperties

  .property object Item(int32)
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 00 00 00 00 ) 
    .get instance object CERTADMINLib.OCSPPropertyCollectionClass::get_Item(int32)
  } // end of property OCSPPropertyCollectionClass::Item
  .property int32 Count()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
    .get instance int32 CERTADMINLib.OCSPPropertyCollectionClass::get_Count()
  } // end of property OCSPPropertyCollectionClass::Count
  .property object ItemByName(string)
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
    .get instance object CERTADMINLib.OCSPPropertyCollectionClass::get_ItemByName(string)
  } // end of property OCSPPropertyCollectionClass::ItemByName
} // end of class CERTADMINLib.OCSPPropertyCollectionClass

.class interface public abstract auto ansi import CERTADMINLib.IOCSPAdmin
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 C0 10 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 32 32 45 38 33 30 44 2D 36 37 44 42   // ..$322E830D-67DB
                                                                                                  2D 34 46 45 39 2D 39 35 37 37 2D 34 35 39 36 44   // -4FE9-9577-4596D
                                                                                                  39 46 30 39 32 39 34 00 00 )                      // 9F09294..
  .method public hidebysig newslot specialname abstract virtual 
          instance class CERTADMINLib.OCSPPropertyCollection 
          marshal( interface ) 
          get_OCSPServiceProperties() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
  } // end of method IOCSPAdmin::get_OCSPServiceProperties

  .method public hidebysig newslot specialname abstract virtual 
          instance class CERTADMINLib.IOCSPCAConfigurationCollection 
          marshal( interface ) 
          get_OCSPCAConfigurationCollection() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
  } // end of method IOCSPAdmin::get_OCSPCAConfigurationCollection

  .method public hidebysig newslot abstract virtual 
          instance void  GetConfiguration([in] string  marshal( bstr) bstrServerName,
                                          [in] bool bForce) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 00 00 00 00 ) 
  } // end of method IOCSPAdmin::GetConfiguration

  .method public hidebysig newslot abstract virtual 
          instance void  SetConfiguration([in] string  marshal( bstr) bstrServerName,
                                          [in] bool bForce) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 00 00 00 00 ) 
  } // end of method IOCSPAdmin::SetConfiguration

  .method public hidebysig newslot abstract virtual 
          instance int32  GetMyRoles([in] string  marshal( bstr) bstrServerName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 00 00 00 00 ) 
  } // end of method IOCSPAdmin::GetMyRoles

  .method public hidebysig newslot abstract virtual 
          instance void  Ping([in] string  marshal( bstr) bstrServerName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 00 00 00 00 ) 
  } // end of method IOCSPAdmin::Ping

  .method public hidebysig newslot abstract virtual 
          instance void  SetSecurity([in] string  marshal( bstr) bstrServerName,
                                     [in] string  marshal( bstr) bstrVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 00 00 00 00 ) 
  } // end of method IOCSPAdmin::SetSecurity

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetSecurity([in] string  marshal( bstr) bstrServerName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
  } // end of method IOCSPAdmin::GetSecurity

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetSigningCertificates([in] string  marshal( bstr) bstrServerName,
                                 [in] object&  marshal( struct) pCACertVar) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 00 00 00 00 ) 
  } // end of method IOCSPAdmin::GetSigningCertificates

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetHashAlgorithms([in] string  marshal( bstr) bstrServerName,
                            [in] string  marshal( bstr) bstrCAId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 00 00 00 00 ) 
  } // end of method IOCSPAdmin::GetHashAlgorithms

  .property class CERTADMINLib.OCSPPropertyCollection
          OCSPServiceProperties()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
    .get instance class CERTADMINLib.OCSPPropertyCollection CERTADMINLib.IOCSPAdmin::get_OCSPServiceProperties()
  } // end of property IOCSPAdmin::OCSPServiceProperties
  .property class CERTADMINLib.IOCSPCAConfigurationCollection
          OCSPCAConfigurationCollection()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
    .get instance class CERTADMINLib.IOCSPCAConfigurationCollection CERTADMINLib.IOCSPAdmin::get_OCSPCAConfigurationCollection()
  } // end of property IOCSPAdmin::OCSPCAConfigurationCollection
} // end of class CERTADMINLib.IOCSPAdmin

.class interface public abstract auto ansi import CERTADMINLib.OCSPAdmin
       implements CERTADMINLib.IOCSPAdmin
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 32 32 45 38 33 30 44 2D 36 37 44 42   // ..$322E830D-67DB
                                                                                                  2D 34 46 45 39 2D 39 35 37 37 2D 34 35 39 36 44   // -4FE9-9577-4596D
                                                                                                  39 46 30 39 32 39 34 00 00 )                      // 9F09294..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 1B 43 45 52 54 41 44 4D 49 4E 4C 69 62 2E   // ...CERTADMINLib.
                                                                                                                          4F 43 53 50 41 64 6D 69 6E 43 6C 61 73 73 00 00 ) // OCSPAdminClass..
} // end of class CERTADMINLib.OCSPAdmin

.class public auto ansi import CERTADMINLib.OCSPAdminClass
       extends [mscorlib]System.Object
       implements CERTADMINLib.IOCSPAdmin,
                  CERTADMINLib.OCSPAdmin
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 44 33 46 37 33 35 31 31 2D 39 32 43 39   // ..$D3F73511-92C9
                                                                                                  2D 34 37 43 42 2D 38 46 46 32 2D 38 44 38 39 31   // -47CB-8FF2-8D891
                                                                                                  41 37 43 34 44 45 34 00 00 )                      // A7C4DE4..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method OCSPAdminClass::.ctor

  .method public hidebysig newslot specialname virtual 
          instance class CERTADMINLib.OCSPPropertyCollection 
          marshal( interface ) 
          get_OCSPServiceProperties() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPAdmin::get_OCSPServiceProperties
  } // end of method OCSPAdminClass::get_OCSPServiceProperties

  .method public hidebysig newslot specialname virtual 
          instance class CERTADMINLib.IOCSPCAConfigurationCollection 
          marshal( interface ) 
          get_OCSPCAConfigurationCollection() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPAdmin::get_OCSPCAConfigurationCollection
  } // end of method OCSPAdminClass::get_OCSPCAConfigurationCollection

  .method public hidebysig newslot virtual 
          instance void  GetConfiguration([in] string  marshal( bstr) bstrServerName,
                                          [in] bool bForce) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPAdmin::GetConfiguration
  } // end of method OCSPAdminClass::GetConfiguration

  .method public hidebysig newslot virtual 
          instance void  SetConfiguration([in] string  marshal( bstr) bstrServerName,
                                          [in] bool bForce) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPAdmin::SetConfiguration
  } // end of method OCSPAdminClass::SetConfiguration

  .method public hidebysig newslot virtual 
          instance int32  GetMyRoles([in] string  marshal( bstr) bstrServerName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPAdmin::GetMyRoles
  } // end of method OCSPAdminClass::GetMyRoles

  .method public hidebysig newslot virtual 
          instance void  Ping([in] string  marshal( bstr) bstrServerName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPAdmin::Ping
  } // end of method OCSPAdminClass::Ping

  .method public hidebysig newslot virtual 
          instance void  SetSecurity([in] string  marshal( bstr) bstrServerName,
                                     [in] string  marshal( bstr) bstrVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPAdmin::SetSecurity
  } // end of method OCSPAdminClass::SetSecurity

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetSecurity([in] string  marshal( bstr) bstrServerName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPAdmin::GetSecurity
  } // end of method OCSPAdminClass::GetSecurity

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetSigningCertificates([in] string  marshal( bstr) bstrServerName,
                                 [in] object&  marshal( struct) pCACertVar) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPAdmin::GetSigningCertificates
  } // end of method OCSPAdminClass::GetSigningCertificates

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetHashAlgorithms([in] string  marshal( bstr) bstrServerName,
                            [in] string  marshal( bstr) bstrCAId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 00 00 00 00 ) 
    .override CERTADMINLib.IOCSPAdmin::GetHashAlgorithms
  } // end of method OCSPAdminClass::GetHashAlgorithms

  .property class CERTADMINLib.OCSPPropertyCollection
          OCSPServiceProperties()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
    .get instance class CERTADMINLib.OCSPPropertyCollection CERTADMINLib.OCSPAdminClass::get_OCSPServiceProperties()
  } // end of property OCSPAdminClass::OCSPServiceProperties
  .property class CERTADMINLib.IOCSPCAConfigurationCollection
          OCSPCAConfigurationCollection()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
    .get instance class CERTADMINLib.IOCSPCAConfigurationCollection CERTADMINLib.OCSPAdminClass::get_OCSPCAConfigurationCollection()
  } // end of property OCSPAdminClass::OCSPCAConfigurationCollection
} // end of class CERTADMINLib.OCSPAdminClass

.class interface public abstract auto ansi import CERTADMINLib.IEnumCERTVIEWCOLUMN
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 39 43 37 33 35 42 45 32 2D 35 37 41 35   // ..$9C735BE2-57A5
                                                                                                  2D 31 31 44 31 2D 39 42 44 42 2D 30 30 43 30 34   // -11D1-9BDB-00C04
                                                                                                  46 42 36 38 33 46 41 00 00 )                      // FB683FA..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .method public hidebysig newslot abstract virtual 
          instance int32  Next() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWCOLUMN::Next

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetName() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWCOLUMN::GetName

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetDisplayName() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWCOLUMN::GetDisplayName

  .method public hidebysig newslot abstract virtual 
          instance int32  GetType() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWCOLUMN::GetType

  .method public hidebysig newslot abstract virtual 
          instance int32  IsIndexed() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWCOLUMN::IsIndexed

  .method public hidebysig newslot abstract virtual 
          instance int32  GetMaxLength() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWCOLUMN::GetMaxLength

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetValue([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWCOLUMN::GetValue

  .method public hidebysig newslot abstract virtual 
          instance void  Skip([in] int32 celt) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWCOLUMN::Skip

  .method public hidebysig newslot abstract virtual 
          instance void  Reset() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWCOLUMN::Reset

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWCOLUMN 
          marshal( interface ) 
          Clone() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWCOLUMN::Clone

} // end of class CERTADMINLib.IEnumCERTVIEWCOLUMN

.class interface public abstract auto ansi import CERTADMINLib.IEnumCERTVIEWROW
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 44 31 31 35 37 46 34 43 2D 35 41 46 32   // ..$D1157F4C-5AF2
                                                                                                  2D 31 31 44 31 2D 39 42 44 43 2D 30 30 43 30 34   // -11D1-9BDC-00C04
                                                                                                  46 42 36 38 33 46 41 00 00 )                      // FB683FA..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .method public hidebysig newslot abstract virtual 
          instance int32  Next() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWROW::Next

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWCOLUMN 
          marshal( interface ) 
          EnumCertViewColumn() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWROW::EnumCertViewColumn

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWATTRIBUTE 
          marshal( interface ) 
          EnumCertViewAttribute([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWROW::EnumCertViewAttribute

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWEXTENSION 
          marshal( interface ) 
          EnumCertViewExtension([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWROW::EnumCertViewExtension

  .method public hidebysig newslot abstract virtual 
          instance void  Skip([in] int32 celt) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWROW::Skip

  .method public hidebysig newslot abstract virtual 
          instance void  Reset() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWROW::Reset

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWROW 
          marshal( interface ) 
          Clone() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWROW::Clone

  .method public hidebysig newslot abstract virtual 
          instance int32  GetMaxIndex() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWROW::GetMaxIndex

} // end of class CERTADMINLib.IEnumCERTVIEWROW

.class interface public abstract auto ansi import CERTADMINLib.IOCSPProperty
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 C0 10 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 36 36 46 42 37 38 33 39 2D 35 46 30 34   // ..$66FB7839-5F04
                                                                                                  2D 34 43 32 35 2D 41 44 31 38 2D 39 46 46 31 41   // -4C25-AD18-9FF1A
                                                                                                  38 33 37 36 45 45 30 00 00 )                      // 8376EE0..
  .method public hidebysig newslot specialname abstract virtual 
          instance string 
          marshal( bstr) 
          get_Name() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
  } // end of method IOCSPProperty::get_Name

  .method public hidebysig newslot specialname abstract virtual 
          instance object 
          marshal( struct) 
          get_Value() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
  } // end of method IOCSPProperty::get_Value

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_Value([in] object  marshal( struct) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
  } // end of method IOCSPProperty::set_Value

  .method public hidebysig newslot specialname abstract virtual 
          instance bool  get_Modified() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 00 00 00 00 ) 
  } // end of method IOCSPProperty::get_Modified

  .property string Name()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
    .get instance string CERTADMINLib.IOCSPProperty::get_Name()
  } // end of property IOCSPProperty::Name
  .property object Value()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
    .get instance object CERTADMINLib.IOCSPProperty::get_Value()
    .set instance void CERTADMINLib.IOCSPProperty::set_Value(object)
  } // end of property IOCSPProperty::Value
  .property bool Modified()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 00 00 00 00 ) 
    .get instance bool CERTADMINLib.IOCSPProperty::get_Modified()
  } // end of property IOCSPProperty::Modified
} // end of class CERTADMINLib.IOCSPProperty

.class interface public abstract auto ansi import CERTADMINLib.IOCSPCAConfigurationCollection
       implements [mscorlib]System.Collections.IEnumerable
{
  .custom instance void [mscorlib]System.Reflection.DefaultMemberAttribute::.ctor(string) = ( 01 00 04 49 74 65 6D 00 00 )                      // ...Item..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 32 42 45 42 45 41 30 42 2D 35 45 43 45   // ..$2BEBEA0B-5ECE
                                                                                                  2D 34 46 32 38 2D 41 39 31 43 2D 38 36 42 34 42   // -4F28-A91C-86B4B
                                                                                                  42 32 30 46 30 44 33 00 00 )                      // B20F0D3..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 C0 10 00 00 00 00 ) 
  .method public hidebysig newslot abstract virtual 
          instance class [mscorlib]System.Collections.IEnumerator 
          marshal( custom ("System.Runtime.InteropServices.CustomMarshalers.EnumeratorToEnumVariantMarshaler, CustomMarshalers, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a","")) 
          GetEnumerator() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 FC FF FF FF 00 00 ) 
  } // end of method IOCSPCAConfigurationCollection::GetEnumerator

  .method public hidebysig newslot specialname abstract virtual 
          instance object 
          marshal( struct) 
          get_Item([in] int32 Index) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfigurationCollection::get_Item

  .method public hidebysig newslot specialname abstract virtual 
          instance int32  get_Count() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfigurationCollection::get_Count

  .method public hidebysig newslot specialname abstract virtual 
          instance object 
          marshal( struct) 
          get_ItemByName([in] string  marshal( bstr) bstrIdentifier) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfigurationCollection::get_ItemByName

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IOCSPCAConfiguration 
          marshal( interface ) 
          CreateCAConfiguration([in] string  marshal( bstr) bstrIdentifier,
                                [in] object  marshal( struct) varCACert) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfigurationCollection::CreateCAConfiguration

  .method public hidebysig newslot abstract virtual 
          instance void  DeleteCAConfiguration([in] string  marshal( bstr) bstrIdentifier) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfigurationCollection::DeleteCAConfiguration

  .property object Item(int32)
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 00 00 00 00 ) 
    .get instance object CERTADMINLib.IOCSPCAConfigurationCollection::get_Item(int32)
  } // end of property IOCSPCAConfigurationCollection::Item
  .property int32 Count()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
    .get instance int32 CERTADMINLib.IOCSPCAConfigurationCollection::get_Count()
  } // end of property IOCSPCAConfigurationCollection::Count
  .property object ItemByName(string)
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
    .get instance object CERTADMINLib.IOCSPCAConfigurationCollection::get_ItemByName(string)
  } // end of property IOCSPCAConfigurationCollection::ItemByName
} // end of class CERTADMINLib.IOCSPCAConfigurationCollection

.class interface public abstract auto ansi import CERTADMINLib.IEnumCERTVIEWATTRIBUTE
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 45 37 37 44 42 36 35 36 2D 37 36 35 33   // ..$E77DB656-7653
                                                                                                  2D 31 31 44 31 2D 39 42 44 45 2D 30 30 43 30 34   // -11D1-9BDE-00C04
                                                                                                  46 42 36 38 33 46 41 00 00 )                      // FB683FA..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .method public hidebysig newslot abstract virtual 
          instance int32  Next() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWATTRIBUTE::Next

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetName() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWATTRIBUTE::GetName

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetValue() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWATTRIBUTE::GetValue

  .method public hidebysig newslot abstract virtual 
          instance void  Skip([in] int32 celt) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWATTRIBUTE::Skip

  .method public hidebysig newslot abstract virtual 
          instance void  Reset() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWATTRIBUTE::Reset

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWATTRIBUTE 
          marshal( interface ) 
          Clone() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWATTRIBUTE::Clone

} // end of class CERTADMINLib.IEnumCERTVIEWATTRIBUTE

.class interface public abstract auto ansi import CERTADMINLib.IEnumCERTVIEWEXTENSION
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 45 37 44 44 31 34 36 36 2D 37 36 35 33   // ..$E7DD1466-7653
                                                                                                  2D 31 31 44 31 2D 39 42 44 45 2D 30 30 43 30 34   // -11D1-9BDE-00C04
                                                                                                  46 42 36 38 33 46 41 00 00 )                      // FB683FA..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .method public hidebysig newslot abstract virtual 
          instance int32  Next() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWEXTENSION::Next

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetName() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWEXTENSION::GetName

  .method public hidebysig newslot abstract virtual 
          instance int32  GetFlags() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWEXTENSION::GetFlags

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetValue([in] int32 Type,
                   [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWEXTENSION::GetValue

  .method public hidebysig newslot abstract virtual 
          instance void  Skip([in] int32 celt) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWEXTENSION::Skip

  .method public hidebysig newslot abstract virtual 
          instance void  Reset() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWEXTENSION::Reset

  .method public hidebysig newslot abstract virtual 
          instance class CERTADMINLib.IEnumCERTVIEWEXTENSION 
          marshal( interface ) 
          Clone() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method IEnumCERTVIEWEXTENSION::Clone

} // end of class CERTADMINLib.IEnumCERTVIEWEXTENSION

.class public auto ansi sealed CERTADMINLib.OCSPSigningFlag
       extends [mscorlib]System.Enum
{
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTADMINLib.OCSPSigningFlag OCSP_SF_SILENT = int32(0x00000001)
  .field public static literal valuetype CERTADMINLib.OCSPSigningFlag OCSP_SF_USE_CACERT = int32(0x00000002)
  .field public static literal valuetype CERTADMINLib.OCSPSigningFlag OCSP_SF_ALLOW_SIGNINGCERT_AUTORENEWAL = int32(0x00000004)
  .field public static literal valuetype CERTADMINLib.OCSPSigningFlag OCSP_SF_FORCE_SIGNINGCERT_ISSUER_ISCA = int32(0x00000008)
  .field public static literal valuetype CERTADMINLib.OCSPSigningFlag OCSP_SF_AUTODISCOVER_SIGNINGCERT = int32(0x00000010)
  .field public static literal valuetype CERTADMINLib.OCSPSigningFlag OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT = int32(0x00000020)
  .field public static literal valuetype CERTADMINLib.OCSPSigningFlag OCSP_SF_RESPONDER_ID_KEYHASH = int32(0x00000040)
  .field public static literal valuetype CERTADMINLib.OCSPSigningFlag OCSP_SF_RESPONDER_ID_NAME = int32(0x00000080)
  .field public static literal valuetype CERTADMINLib.OCSPSigningFlag OCSP_SF_ALLOW_NONCE_EXTENSION = int32(0x00000100)
  .field public static literal valuetype CERTADMINLib.OCSPSigningFlag OCSP_SF_ALLOW_SIGNINGCERT_AUTOENROLLMENT = int32(0x00000200)
} // end of class CERTADMINLib.OCSPSigningFlag

.class public auto ansi sealed CERTADMINLib.OCSPRequestFlag
       extends [mscorlib]System.Enum
{
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTADMINLib.OCSPRequestFlag OCSP_RF_REJECT_SIGNED_REQUESTS = int32(0x00000001)
} // end of class CERTADMINLib.OCSPRequestFlag

.class interface public abstract auto ansi import CERTADMINLib.IOCSPCAConfiguration
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 41 45 43 39 32 42 34 30 2D 33 44 34 36   // ..$AEC92B40-3D46
                                                                                                  2D 34 33 33 46 2D 38 37 44 31 2D 42 38 34 44 35   // -433F-87D1-B84D5
                                                                                                  43 31 45 37 39 30 44 00 00 )                      // C1E790D..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 C0 10 00 00 00 00 ) 
  .method public hidebysig newslot specialname abstract virtual 
          instance string 
          marshal( bstr) 
          get_Identifier() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_Identifier

  .method public hidebysig newslot specialname abstract virtual 
          instance object 
          marshal( struct) 
          get_CACertificate() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_CACertificate

  .method public hidebysig newslot specialname abstract virtual 
          instance string 
          marshal( bstr) 
          get_HashAlgorithm() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_HashAlgorithm

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_HashAlgorithm([in] string  marshal( bstr) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::set_HashAlgorithm

  .method public hidebysig newslot specialname abstract virtual 
          instance uint32  get_SigningFlags() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_SigningFlags

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_SigningFlags([in] uint32 pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::set_SigningFlags

  .method public hidebysig newslot specialname abstract virtual 
          instance object 
          marshal( struct) 
          get_SigningCertificate() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_SigningCertificate

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_SigningCertificate([in] object  marshal( struct) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::set_SigningCertificate

  .method public hidebysig newslot specialname abstract virtual 
          instance uint32  get_ReminderDuration() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_ReminderDuration

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_ReminderDuration([in] uint32 pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::set_ReminderDuration

  .method public hidebysig newslot specialname abstract virtual 
          instance uint32  get_ErrorCode() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_ErrorCode

  .method public hidebysig newslot specialname abstract virtual 
          instance string 
          marshal( bstr) 
          get_CSPName() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_CSPName

  .method public hidebysig newslot specialname abstract virtual 
          instance uint32  get_KeySpec() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_KeySpec

  .method public hidebysig newslot specialname abstract virtual 
          instance string 
          marshal( bstr) 
          get_ProviderCLSID() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_ProviderCLSID

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_ProviderCLSID([in] string  marshal( bstr) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::set_ProviderCLSID

  .method public hidebysig newslot specialname abstract virtual 
          instance object 
          marshal( struct) 
          get_ProviderProperties() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0B 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_ProviderProperties

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_ProviderProperties([in] object  marshal( struct) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0B 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::set_ProviderProperties

  .method public hidebysig newslot specialname abstract virtual 
          instance bool  get_Modified() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0C 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_Modified

  .method public hidebysig newslot specialname abstract virtual 
          instance object 
          marshal( struct) 
          get_LocalRevocationInformation() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0D 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_LocalRevocationInformation

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_LocalRevocationInformation([in] object  marshal( struct) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0D 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::set_LocalRevocationInformation

  .method public hidebysig newslot specialname abstract virtual 
          instance string 
          marshal( bstr) 
          get_SigningCertificateTemplate() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0E 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_SigningCertificateTemplate

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_SigningCertificateTemplate([in] string  marshal( bstr) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0E 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::set_SigningCertificateTemplate

  .method public hidebysig newslot specialname abstract virtual 
          instance string 
          marshal( bstr) 
          get_CAConfig() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0F 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::get_CAConfig

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_CAConfig([in] string  marshal( bstr) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0F 00 00 00 00 00 ) 
  } // end of method IOCSPCAConfiguration::set_CAConfig

  .property string Identifier()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 00 00 00 00 ) 
    .get instance string CERTADMINLib.IOCSPCAConfiguration::get_Identifier()
  } // end of property IOCSPCAConfiguration::Identifier
  .property object CACertificate()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
    .get instance object CERTADMINLib.IOCSPCAConfiguration::get_CACertificate()
  } // end of property IOCSPCAConfiguration::CACertificate
  .property string HashAlgorithm()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 00 00 00 00 ) 
    .set instance void CERTADMINLib.IOCSPCAConfiguration::set_HashAlgorithm(string)
    .get instance string CERTADMINLib.IOCSPCAConfiguration::get_HashAlgorithm()
  } // end of property IOCSPCAConfiguration::HashAlgorithm
  .property uint32 SigningFlags()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 00 00 00 00 ) 
    .get instance uint32 CERTADMINLib.IOCSPCAConfiguration::get_SigningFlags()
    .set instance void CERTADMINLib.IOCSPCAConfiguration::set_SigningFlags(uint32)
  } // end of property IOCSPCAConfiguration::SigningFlags
  .property object SigningCertificate()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 00 00 00 00 ) 
    .set instance void CERTADMINLib.IOCSPCAConfiguration::set_SigningCertificate(object)
    .get instance object CERTADMINLib.IOCSPCAConfiguration::get_SigningCertificate()
  } // end of property IOCSPCAConfiguration::SigningCertificate
  .property uint32 ReminderDuration()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 00 00 00 00 ) 
    .set instance void CERTADMINLib.IOCSPCAConfiguration::set_ReminderDuration(uint32)
    .get instance uint32 CERTADMINLib.IOCSPCAConfiguration::get_ReminderDuration()
  } // end of property IOCSPCAConfiguration::ReminderDuration
  .property uint32 ErrorCode()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 00 00 00 00 ) 
    .get instance uint32 CERTADMINLib.IOCSPCAConfiguration::get_ErrorCode()
  } // end of property IOCSPCAConfiguration::ErrorCode
  .property string CSPName()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
    .get instance string CERTADMINLib.IOCSPCAConfiguration::get_CSPName()
  } // end of property IOCSPCAConfiguration::CSPName
  .property uint32 KeySpec()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 00 00 00 00 ) 
    .get instance uint32 CERTADMINLib.IOCSPCAConfiguration::get_KeySpec()
  } // end of property IOCSPCAConfiguration::KeySpec
  .property string ProviderCLSID()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 00 00 00 00 ) 
    .get instance string CERTADMINLib.IOCSPCAConfiguration::get_ProviderCLSID()
    .set instance void CERTADMINLib.IOCSPCAConfiguration::set_ProviderCLSID(string)
  } // end of property IOCSPCAConfiguration::ProviderCLSID
  .property object ProviderProperties()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0B 00 00 00 00 00 ) 
    .get instance object CERTADMINLib.IOCSPCAConfiguration::get_ProviderProperties()
    .set instance void CERTADMINLib.IOCSPCAConfiguration::set_ProviderProperties(object)
  } // end of property IOCSPCAConfiguration::ProviderProperties
  .property bool Modified()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0C 00 00 00 00 00 ) 
    .get instance bool CERTADMINLib.IOCSPCAConfiguration::get_Modified()
  } // end of property IOCSPCAConfiguration::Modified
  .property object LocalRevocationInformation()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0D 00 00 00 00 00 ) 
    .get instance object CERTADMINLib.IOCSPCAConfiguration::get_LocalRevocationInformation()
    .set instance void CERTADMINLib.IOCSPCAConfiguration::set_LocalRevocationInformation(object)
  } // end of property IOCSPCAConfiguration::LocalRevocationInformation
  .property string SigningCertificateTemplate()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0E 00 00 00 00 00 ) 
    .set instance void CERTADMINLib.IOCSPCAConfiguration::set_SigningCertificateTemplate(string)
    .get instance string CERTADMINLib.IOCSPCAConfiguration::get_SigningCertificateTemplate()
  } // end of property IOCSPCAConfiguration::SigningCertificateTemplate
  .property string CAConfig()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0F 00 00 00 00 00 ) 
    .get instance string CERTADMINLib.IOCSPCAConfiguration::get_CAConfig()
    .set instance void CERTADMINLib.IOCSPCAConfiguration::set_CAConfig(string)
  } // end of property IOCSPCAConfiguration::CAConfig
} // end of class CERTADMINLib.IOCSPCAConfiguration


// =============================================================

// *********** DISASSEMBLY COMPLETE ***********************
// WARNING: Created Win32 resource file certadm.res
