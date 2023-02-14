namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Contains enumeration to identify data type in <see cref="SignedContentBlob"/> object.
/// </summary>
public enum ContentBlobType {
    /// <summary>
    /// Data type is signed content blob with attached signature and signature information.
    /// </summary>
    SignedBlob,
    /// <summary>
    /// Arbitrary data to be signed.
    /// </summary>
    ToBeSignedBlob
}