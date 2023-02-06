using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Specifies an algorithm used to encrypt or sign data. This class includes the object identifier
/// (<strong>OID</strong>) of the algorithm and any needed parameters for that algorithm. 
/// </summary>
/// <remarks>This class supports PKCS#2.1 signature format.</remarks>
public class AlgorithmIdentifier {
    readonly List<Byte> _rawData = new();
    Oid algId;
    Byte[] param;

    /// <summary>
    /// Initializes a new instance of the <strong>AlgorithmIdentifier</strong> class from a ASN.1-encoded
    /// byte array that represents an <strong>AlgorithmIdentifier</strong> structure.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    public AlgorithmIdentifier(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        decode(rawData);
    }
    ///// <summary>
    ///// Initializes a new instance of the <strong>AlgorithmIdentifier</strong> class from an algorithm
    ///// object identifier without parameters.
    ///// </summary>
    ///// <param name="oid">Algorithm object identifier.</param>
    //public AlgorithmIdentifier(Oid oid) : this(oid, null) { }
    ///  <summary>
    ///  Initializes a new instance of the <strong>AlgorithmIdentifier</strong> class from an algorithm
    ///  object identifier and, optionally, algorithm parameters.
    ///  </summary>
    ///  <param name="oid">Algorithm object identifier.</param>
    ///  <param name="parameters">
    /// 		A ASN.1-encoded byte array that represents algorithm parameters.
    ///  
    /// 		This parameter can be <strong>NULL</strong>.
    ///  </param>
    ///  <exception cref="ArgumentNullException">
    ///     <strong>oid</strong> parameter is null.
    /// </exception>
    /// <remarks>
    ///     For signature algorithm identifiers you often add explicit parameters. If there are no explicit parameters (such as when
    ///     RSA-based signature is used) you should pass empty array in <strong>parameters</strong> parameter. When explicit parameters
    ///     are not used (such as when hashing or other algorithm group), you must pass <strong>null</strong> value to
    ///     <strong>parameters</strong> parameter.
    /// </remarks>
    public AlgorithmIdentifier(Oid oid, Byte[] parameters) {
        if (oid == null) {
            throw new ArgumentNullException(nameof(oid));
        }
        encode(oid, parameters);
    }

    /// <summary>
    /// Gets an object identifier of an algorithm.
    /// </summary>
    public Oid AlgorithmId => new(algId.Value, algId.FriendlyName);
    /// <summary>
    /// Gets a byte array that provides encoded algorithm-specific parameters. In many cases, there are no
    /// parameters.
    /// </summary>
    public Byte[] Parameters => param?.ToArray();
    /// <summary>
    /// Gets algorithm identifier ASN.1-encoded byte array.
    /// </summary>
    public Byte[] RawData => _rawData.ToArray();

    void decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
        algId = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData());
        if (asn.MoveNext()) {
            param = asn.GetTagRawData();
        }
        _rawData.AddRange(rawData);
    }
    void encode(Oid oid, Byte[] parameters) {
        // if empty array received, then parameters is set to ASN.1 NULL type => 5, 0
        param = parameters is { Length: 0 }
            ? new Byte[] { 5, 0 }
            : parameters;

        algId = oid;
        var rawBytes = new List<Byte>(Asn1Utils.EncodeObjectIdentifier(oid));
        if (param != null) {
            rawBytes.AddRange(param);
        }
            
        _rawData.AddRange(Asn1Utils.Encode(rawBytes.ToArray(), 48));
    }

    /// <summary>
    /// Formats a current object to string.
    /// </summary>
    /// <returns>Formatted string.</returns>
    public override String ToString() {
        var sb = new StringBuilder();
        var algParamString = new StringBuilder();
        if (param == null) {
            algParamString.Append(" NULL");
        } else {
            algParamString.Append(Environment.NewLine + "    ");
            EncodingType format = EncodingType.Hex;
            if (param.Length > 16) {
                format = EncodingType.HexAddress;
            }
            algParamString.Append(
                AsnFormatter.BinaryToString(param, format)
                    .Replace(Environment.NewLine, Environment.NewLine + "    ")
                    .TrimEnd());
        }
        sb.Append(
            // TODO: algorithm identifier is more than signature algorithm identifier, it is commonly used
            // TODO: structure type in X.509 and PKCS world
            $@"Signature Algorithm:
    Algorithm ObjectId: {AlgorithmId.Format(true)}
    Algorithm Parameters:{algParamString}
");
        return sb.ToString();
    }
}