using System;
using CERTADMINLib;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents basic information about Online Responder array members.
    /// </summary>
    public class OcspResponderMemberInfo {

        internal OcspResponderMemberInfo(String serverName) {
            ComputerName = serverName;
            var ocspAdmin = new OCSPAdminClass();
            try {
                ocspAdmin.Ping(serverName);
                IsRunning = true;
            } catch { }
        }
        /// <summary>
        /// Gets the Online Responder host name.
        /// </summary>
        public String ComputerName { get; }
        /// <summary>
        /// Gets the Online Responder service status on array member.
        /// </summary>
        public Boolean IsRunning { get; }

        /// <summary>
        /// Connects to an Online Responder array member.
        /// </summary>
        /// <returns>Online Responder object.</returns>
        public OcspResponder Connect() {
            return OcspResponder.Connect(ComputerName);
        }

        /// <inheritdoc />
        public override String ToString() {
            String status = IsRunning ? "online" : "offline";
            return $"{ComputerName} ({status})";
        }
    }
}