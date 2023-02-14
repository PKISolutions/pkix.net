using System;
using PKI.Structs;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;
/// <summary>
/// Represents private key provider and container information.
/// </summary>
public class KeyProviderInfo {
    internal KeyProviderInfo(Wincrypt.CRYPT_KEY_PROV_INFO provInfo) {
        ProviderName = provInfo.pwszProvName;
        ProviderType = provInfo.dwProvType;
        ContainerName = provInfo.pwszContainerName;
        Flags = provInfo.dwFlags;

    }

    /// <summary>
    /// Gets the provider name.
    /// </summary>
    public String ProviderName { get; }
    /// <summary>
    /// Gets the provider type.
    /// </summary>
    public Int32 ProviderType { get; }
    /// <summary>
    /// Gets the key container name.
    /// </summary>
    public String ContainerName { get; }
    /// <summary>
    /// Gets key flags.
    /// </summary>
    public Int32 Flags { get; }
    /// <summary>
    /// Gets the key's KeySpec.
    /// </summary>
    public X509KeySpecFlags KeySpec { get; }
}