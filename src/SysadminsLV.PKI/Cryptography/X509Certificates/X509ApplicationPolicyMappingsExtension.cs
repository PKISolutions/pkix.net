using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents application policy mappings certificate extension.
/// </summary>
/// <remarks><see cref="X509Extension.Critical"/> member is always set to <strong>True</strong>.</remarks>
public sealed class X509ApplicationPolicyMappingsExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.ApplicationPolicyMappings);
    readonly OidMappingCollection _mappings = new();

    /// <summary>
    /// Initializes a new instance of the <strong>X509ApplicationPolicyMappingsExtension</strong> class from
    /// an <see cref="AsnEncodedData"/> object.
    /// </summary>
    /// <param name="mappings"></param>
    /// <exception cref="ArgumentNullException">
    /// <strong>mappings</strong> parameter is null.
    /// </exception>
    public X509ApplicationPolicyMappingsExtension(AsnEncodedData mappings) : base(
        _oid, mappings.RawData, true) {
        if (mappings == null) {
            throw new ArgumentNullException(nameof(mappings));
        }
        m_decode(mappings.RawData);
    }
    /// <summary>
    /// Initializes a new instance of the <strong>X509ApplicationPolicyMappingsExtension</strong> class from
    /// a collection of <see cref="OidMapping"/> objects.
    /// </summary>
    /// <param name="mappings">
    /// A collection of <see cref="OidMapping"/> objects.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <strong>mappings</strong> parameter is null or empty. Parameter must include at least one OID mapping
    /// object.
    /// </exception>
    public X509ApplicationPolicyMappingsExtension(OidMapping[] mappings) {
        if (mappings == null || mappings.Length < 1) {
            throw new ArgumentNullException(nameof(mappings));
        }
        m_initialize(mappings);
    }

    /// <summary>
    /// Gets a collection of policy mappings.
    /// </summary>
    public OidMappingCollection OidMappings => new(_mappings);

    void m_initialize(IEnumerable<OidMapping> mappings) {
        Oid = _oid;
        Critical = true;
        var rawData = new List<Byte>();
        if (mappings != null) {
            _mappings.AddRange(mappings);
        }
        foreach (OidMapping mapping in _mappings) {
            rawData.AddRange(mapping.Encode());
        }
        RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    void m_decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        asn.MoveNext();
        do {
            _mappings.Add(new OidMapping(asn.GetTagRawData()));
        } while (asn.MoveNextSibling());
    }
}