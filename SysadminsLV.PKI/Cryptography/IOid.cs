using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents contract custom Object Identifier handlers must implement.
/// </summary>
public interface IOid {
    /// <inheritdoc cref="Oid.FriendlyName"/>
    String FriendlyName { get; }
    /// <inheritdoc cref="Oid.Value"/>
    String Value { get; }
    /// <summary>
    /// Gets the OID group current identifier belongs to.
    /// </summary>
    OidGroup OidGroup { get; }

    /// <summary>
    /// Gets an instance of <see cref="Oid"/> class from current object.
    /// </summary>
    /// <returns>An instance of <see cref="Oid"/> class.</returns>
    Oid ToOid();
}