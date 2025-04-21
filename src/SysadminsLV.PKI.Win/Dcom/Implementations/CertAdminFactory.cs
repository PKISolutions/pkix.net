using System.Runtime.InteropServices;
using CERTADMINLib;
// ReSharper disable SuspiciousTypeConversion.Global

namespace SysadminsLV.PKI.Dcom.Implementations;

/// <summary>
/// Represents factory class for CERTADMINLib COM classes.
/// </summary>
static class CertAdminFactory {
    public static ICertAdmin2 CreateICertAdmin() {
        return (ICertAdmin2)new CCertAdminClass();
    }
    public static ICertView2 CreateICertView() {
        return (ICertView2)new CCertViewClass();
    }
    public static IOCSPAdmin CreateIOCSPAdmin() {
        return (IOCSPAdmin)new OCSPAdminClass();
    }
    public static IOCSPPropertyCollection CreateOCSPPropertyCollection() {
        return (IOCSPPropertyCollection)new OCSPPropertyCollectionClass();
    }

    #region COM classes

    [Guid("37EABAF0-7FB6-11D0-8817-00A0C903B83C")]
    [TypeLibType(TypeLibTypeFlags.FCanCreate)]
    [ClassInterface(ClassInterfaceType.None)]
    [ComImport]
    class CCertAdminClass;

    [Guid("A12D0F7A-1E84-11D1-9BD6-00C04FB683FA")]
    [TypeLibType(TypeLibTypeFlags.FCanCreate)]
    [ClassInterface(ClassInterfaceType.None)]
    [ComImport]
    class CCertViewClass;

    [Guid("D3F73511-92C9-47CB-8FF2-8D891A7C4DE4")]
    [TypeLibType(TypeLibTypeFlags.FCanCreate)]
    [ClassInterface(ClassInterfaceType.None)]
    [ComImport]
    class OCSPAdminClass;

    [Guid("F935A528-BA8A-4DD9-BA79-F283275CB2DE")]
    [TypeLibType(TypeLibTypeFlags.FCanCreate)]
    [ClassInterface(ClassInterfaceType.None)]
    [ComImport]
    class OCSPPropertyCollectionClass;

    #endregion
}