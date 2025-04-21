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
}