using CERTADMINLib;
// ReSharper disable SuspiciousTypeConversion.Global

namespace SysadminsLV.PKI.Dcom.Implementations;

/// <summary>
/// Represents factory class for CERTADMINLib COM classes.
/// </summary>
static class CertAdminFactory {
    public static ICertAdmin2 CreateICertAdmin() {
        return new CCertAdmin();
    }
    public static ICertView2 CreateICertView() {
        return new CCertView();
    }
    public static IOCSPAdmin CreateIOCSPAdmin() {
        return new OCSPAdmin();
    }
    public static IOCSPPropertyCollection CreateOCSPPropertyCollection() {
        return new OCSPPropertyCollection();
    }
}