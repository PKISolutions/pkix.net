using System;
using Interop.CERTENROLLLib;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Cryptography;
/// <summary>
/// The <strong>CspProviderAlgorithmInfo</strong> class represents an algorithm implemented by a cryptographic
/// provider. Providers are separate modules that implement encryption, hashing, signing, and key exchange
/// (archival) algorithms. Similar providers are grouped together in a type.
/// </summary>
/// <remarks>
///		This class has no public constructors. Instead, use <see cref="CspProviderInfoCollection.GetProviderInfo()"/> method to access this object.
/// </remarks>
public class CspProviderAlgorithmInfo {
    internal CspProviderAlgorithmInfo(ICspAlgorithm alg) {
        Name = alg.Name;
        LongName = alg.LongName;
        AlgorithmType = (CspAlgorithmType)alg.Type;
        AlgorithmOperations = (CspAlgorithmOperation)alg.Operations;
        DefaultLength = alg.DefaultLength;
        MinLength = alg.MinLength;
        MaxLength = alg.MaxLength;
        IncrementLength = alg.IncrementLength;
        IsValid = alg.Valid;
        CryptographyUtils.ReleaseCom(alg);
    }

    /// <summary>
    /// Gets the abbreviated algorithm name.
    /// </summary>
    public String Name { get; }
    /// <summary>
    /// Gets the full name of the algorithm.
    /// </summary>
    public String LongName { get; }
    /// <summary>
    /// Gets the algorithm type.
    /// </summary>
    public CspAlgorithmType AlgorithmType { get; }
    /// <summary>
    /// Gets the operations that can be performed by the algorithm.
    /// </summary>
    public CspAlgorithmOperation AlgorithmOperations { get; }
    /// <summary>
    /// Gets the default length of a key.
    /// </summary>
    public Int32 DefaultLength { get; }
    /// <summary>
    /// Gets the minimum permitted length for a key.
    /// </summary>
    public Int32 MinLength { get; }
    /// <summary>
    /// Gets the maximum permitted length for a key.
    /// </summary>
    public Int32 MaxLength { get; }
    /// <summary>
    /// Gets a value, in bits, that can be used to determine valid incremental key lengths for algorithms that
    /// support multiple key sizes.
    /// </summary>
    public Int32 IncrementLength { get; }
    /// <summary>
    /// Gets a Boolean value that specifies whether the algorithm object is valid.
    /// </summary>
    public Boolean IsValid { get; }
}
