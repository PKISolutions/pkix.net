using System;
using System.Security.Cryptography.X509Certificates;

namespace PKI.ManagedAPI {
    /// <summary>
    /// Contains safe implementations of unmanaged functions.
    /// </summary>
    [Obsolete]
    class ManagedCryptUI {
        /// <summary>
        /// Displays a X.509 Certificate Revocation List UI dialog.
        /// </summary>
        /// <param name="crl">An object to display.</param>
        [Obsolete("Use X509CRL2.ShowUI() method instead.", true)]
        public static void DisplayCRL(X509CRL2 crl) {
            crl.ShowUI();
        }
        /// <summary>
        /// Displays a X.509 Certificate Trust List UI dialog.
        /// </summary>
        /// <param name="ctl">An object to display.</param>
        [Obsolete("Use X509CTL.ShowUI() method instead.", true)]
        public static void DisplayCTL(X509CTL ctl) {
            ctl.ShowUI();
        }
    }
}
