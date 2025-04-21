using System.Runtime.InteropServices;
using CERTCLILib;

namespace SysadminsLV.PKI.Dcom.Implementations;

static class CertCliFactory {
    public static ICertConfig2 CreateCertConfig() {
        return (ICertConfig2)new CCertConfigClass();
    }
    public static ICertGetConfig CreateCertGetConfig() {
        return (ICertGetConfig)new CCertGetConfigClass();
    }
    public static ICertRequest3 CreateCertRequest() {
        return (ICertRequest3)new CCertRequestClass();
    }

    #region COM classes

    [Guid("372FCE38-4324-11D0-8810-00A0C903B83C")]
    [TypeLibType(TypeLibTypeFlags.FCanCreate)]
    [ClassInterface(ClassInterfaceType.None)]
    [ComImport]
    class CCertConfigClass;

    [Guid("C6CC49B0-CE17-11D0-8833-00A0C903B83C")]
    [TypeLibType(TypeLibTypeFlags.FCanCreate)]
    [ClassInterface(ClassInterfaceType.None)]
    [ComImport]
    class CCertGetConfigClass;

    [Guid("98AFF3F0-5524-11D0-8812-00A0C903B83C")]
    [TypeLibType(TypeLibTypeFlags.FCanCreate)]
    [ClassInterface(ClassInterfaceType.None)]
    [ComImport]
    class CCertRequestClass;

    #endregion
}
