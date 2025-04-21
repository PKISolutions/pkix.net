using CERTCLILib;

namespace SysadminsLV.PKI.Dcom.Implementations;

static class CertCliFactory {
    public static ICertConfig2 CreateCertConfig() {
        return new CCertConfig();
    }
    public static ICertGetConfig CreateCertGetConfig() {
        return new CCertGetConfig();
    }
    public static ICertRequest3 CreateCertRequest() {
        return new CCertRequest();
    }
}
