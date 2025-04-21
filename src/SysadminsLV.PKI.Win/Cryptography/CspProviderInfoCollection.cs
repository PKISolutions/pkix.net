using System;
using System.Linq;
using Interop.CERTENROLLLib;
using SysadminsLV.PKI.Dcom.Implementations;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Cryptography;
/// <summary>
/// Represents a collection of <see cref="CspProviderInfo"/> objects.
/// </summary>
public class CspProviderInfoCollection : BasicCollection<CspProviderInfo> {
    /// <summary>
    /// Enumerates registered Cryptographic Service Providers (CSP) and Key Storage Providers (KSP),
    /// their information and supported cryptographic algorithms.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// Current platform does not support key storage providers (prior to Windows Vista).
    /// </exception>
    /// <returns>A collection of registered providers.</returns>
    public static CspProviderInfoCollection GetProviderInfo() {
        ICspInformations providers = CertEnrollFactory.CreateCspInformations();
        providers.AddAvailableCsps();
        var retValue = new CspProviderInfoCollection();
        retValue.AddRange(providers.Cast<ICspInformation>()
            .Select(csp => new CspProviderInfo(csp)).ToArray());
        CryptographyUtils.ReleaseCom(providers);
        return retValue;
    }
    /// <summary>
    /// Gets named registered Cryptographic Service Provider (CSP) or Key Storage Provider (KSP), its
    /// information and supported cryptographic algorithms.
    /// </summary>
    /// <param name="name">Cryptographic provider name.</param>
    /// <exception cref="PlatformNotSupportedException">
    /// Current platform does not support key storage providers (prior to Windows Vista).
    /// </exception>
    /// <returns>Specified provider information. Method returns null if provider is not found.</returns>
    public static CspProviderInfo GetProviderInfo(String name) {
        ICspInformations providers = CertEnrollFactory.CreateCspInformations();
        providers.AddAvailableCsps();
        try {
            ICspInformation provider = providers.ItemByName[name];
            return new CspProviderInfo(provider);
        } catch {
            return null;
        }
    }
}
