using System;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;
/// <summary>
/// Identifies the access state to a certificate store object.
/// </summary>
[Flags]
public enum CertificateStoreObjectAccessStateEnum {
    /// <summary>
    /// Set if context property writes are persisted. For instance, not set for
    /// memory store contexts. Set for registry based stores opened as read or write.
    /// Not set for registry based stores opened as read only.
    /// </summary>
    WritePersist            = 0x1,
    /// <summary>
    /// Set if context resides in a SYSTEM or SYSTEM_REGISTRY store.
    /// </summary>
    SystemStore             = 0x2,
    /// <summary>
    /// Set if context resides in a LocalMachine SYSTEM or SYSTEM_REGISTRY store.
    /// </summary>
    LocalMachineSystemStore = 0x4,
    /// <summary>
    /// Set if context resides in a GroupPolicy SYSTEM or SYSTEM_REGISTRY store.
    /// </summary>
    GroupPolicySystemStore  = 0x8
}
