using System;
using System.Collections;
using System.Collections.Generic;
using Interop.CERTENROLLLib;
using PKI.Enrollment.Policy;
using PKI.Utils;

namespace PKI.Enrollment {
    /// <summary>
    /// Represents certificate autoenrollment client.
    /// </summary>
    public class Autoenrollment {
        /// <summary>
        /// Gets autoenrollment state and settings.
        /// </summary>
        /// <param name="userContext">Specifies whether to retrieve autoenrollment for user or machine context.</param>
        /// <returns>Autoenrollment state and settings. TODO</returns>
        public static Int32 GetAutoenrollmentState(Boolean userContext) {
            return (Int32)CryptoRegistry.GetLKey("Autoenrollment", userContext);
        }
        /// <summary>
        /// Gets locally registered enrollment policy server endpoints.
        /// </summary>
        /// <param name="userContext">Specifies whether to retrieve enrollment policy server endpoints for user or machine context.</param>
        /// <exception cref="NotSupportedException">The operating system do not support certificate enrollment policy servers.</exception>
        /// <returns>An array of registered enrollment policy server endpoints.</returns>
        public static PolicyServerClient[] GetPolicyServers(Boolean userContext) {
            if (!CryptographyUtils.TestCepCompat()) { throw new NotSupportedException(); }
            List<PolicyServerClient> policies = new List<PolicyServerClient>();
            X509CertificateEnrollmentContext context = userContext 
                ? X509CertificateEnrollmentContext.ContextUser 
                : X509CertificateEnrollmentContext.ContextMachine;
            foreach (PolicyServerUrlFlags flag in new []{PolicyServerUrlFlags.PsfLocationGroupPolicy, PolicyServerUrlFlags.PsfLocationRegistry}) {
                CX509PolicyServerListManager serverManager = new CX509PolicyServerListManager();
                try {
                    serverManager.Initialize(context, flag);
                    IEnumerator enumerator = serverManager.GetEnumerator();
                    do {
                        if (enumerator.Current != null) {
                            policies.Add(new PolicyServerClient((IX509PolicyServerUrl)enumerator.Current, userContext));
                        }
                    } while (enumerator.MoveNext());
                } finally {
                    CryptographyUtils.ReleaseCom(serverManager);
                }
            }
            return policies.ToArray();
        }
    }
}
