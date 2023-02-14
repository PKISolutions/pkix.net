using System;
using System.Linq;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;
/// <summary>
/// Represents an abstract class for asymmetric key pairs. This class differs from <see cref="AsymmetricAlgorithm"/> by supporting PKCS#1/PKCS#8
/// formats and conversions.
/// </summary>
public abstract class AsymmetricKeyPair : IDisposable {

    protected AsymmetricKeyPair(Oid keyAlgorithm, Boolean publicOnly) {
        Oid = keyAlgorithm;
        PublicOnly = publicOnly;
    }

    /// <summary>
    /// Gets the algorithm identifier for the asymmetric algorithm group stored in the current object.
    /// </summary>
    public Oid Oid { get; }
    /// <summary>
    /// Gets the value that indicates whether the current object stores only public part of
    /// key material. If <strong>False</strong>, then object contains both, public and private components.
    /// </summary>
    public Boolean PublicOnly { get; }

    protected static Byte[] GetPositiveInteger(Byte[] rawInteger) {
        return rawInteger[0] == 0
            ? rawInteger.Skip(1).ToArray()
            : rawInteger;
    }

    /// <summary>
    /// Gets the implementation object for the current asymmetric algorithm.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// Specified asymmetric algorithm is not implemented on a current platform.
    /// </exception>
    /// <returns>
    /// Object that implements particular asymmetric algorithm on a current platform.
    /// </returns>
    public abstract AsymmetricAlgorithm GetAsymmetricKey();
    /// <inheritdoc />
    public abstract void Dispose();
}
