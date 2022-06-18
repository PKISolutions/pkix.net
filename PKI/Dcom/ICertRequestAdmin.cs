using System;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Dcom {
    public interface ICertRequestAdmin {
        /// <summary>
        /// Sets or modifies the custom extension for a pending request.
        /// </summary>
        /// <param name="requestID">Specifies the request ID.</param>
        /// <param name="extension">Specifies the configured extension to set or modify.</param>
        void SetCertificateExtension(Int32 requestID, X509Extension extension);
    }
}