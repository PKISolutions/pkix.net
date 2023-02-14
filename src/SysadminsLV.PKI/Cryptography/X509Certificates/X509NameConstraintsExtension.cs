using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// The name constraints extension, which MUST be used only in a CA certificate, indicates a name space
/// within which all subject names in subsequent certificates in a certification path MUST be located.
/// Restrictions apply to the subject distinguished name and apply to subject alternative names.
/// Restrictions apply only when the specified name form is present. If no name of the type is in the
/// certificate, the certificate is acceptable. More details about Name constraints extension processing:
/// <see href="https://tools.ietf.org/html/rfc5280#section-4.2.1.10">RFC 5280</see>.
/// </summary>
public sealed class X509NameConstraintsExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.NameConstraints);
    readonly X509AlternativeNameCollection _permittedSubtree = new();
    readonly X509AlternativeNameCollection _excludedSubtree = new();

    /// <summary>
    /// Initializes a new instance of <strong>X509NameConstraintsExtension</strong> class from
    /// ASN.1-encoded Name Constraints extension value. Name Constraints extension is always marked critical.
    /// </summary>
    /// <exception cref="ArgumentNullException">
    /// <strong>aki</strong> parameter is null;
    /// </exception>
    /// <param name="nameConstraints">An ASN.1-encoded Name Constraints extension value.</param>
    public X509NameConstraintsExtension(AsnEncodedData nameConstraints) : base(_oid, nameConstraints.RawData, true) {
        if (nameConstraints == null) {
            throw new ArgumentNullException(nameof(nameConstraints));
        }
        m_decode(nameConstraints.RawData);
    }
    /// <summary>
    /// Initializes a new instance of <strong>X509NameConstraintsExtension</strong> class from
    /// a collection of explicitly permitted and excluded subtrees. Name Constraints extension is
    /// always marked critical.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// <strong>permittedSubtree</strong> and <strong>excludedSubtree</strong> parameters are null;
    /// </exception>
    /// <param name="permittedSubtree">A collection of explicitly permitted names and name patterns.</param>
    /// <param name="excludedSubtree">A collection of explicitly disallowed names and name patterns.</param>
    /// <remarks>Each subtree alone is optional. However, at least one subtree must be provided.</remarks>
    public X509NameConstraintsExtension(X509AlternativeNameCollection permittedSubtree, X509AlternativeNameCollection excludedSubtree) {
        if (permittedSubtree == null && excludedSubtree == null) {
            throw new ArgumentException("Both, 'permittedSubtree' and 'excludedSubtree' cannot be null.");
        }
        m_initialize(permittedSubtree, excludedSubtree);
    }

    /// <summary>
    /// Gets a collection of explicitly allowed names. Any name matching a restriction in this
    /// collection is valid only if it is not listed in the <see cref="ExcludedSubtree"/> collection.
    /// member.
    /// </summary>
    public X509AlternativeNameCollection PermittedSubtree => new(_permittedSubtree);
    /// <summary>
    /// Gets a collection of explicitly disallowed names. Any name matching a restriction in this
    /// collection is invalid regardless of information appearing in the <see cref="PermittedSubtree"/>
    /// member.
    /// </summary>
    public X509AlternativeNameCollection ExcludedSubtree => new(_excludedSubtree);

    void m_initialize(X509AlternativeNameCollection permittedSubtree, X509AlternativeNameCollection excludedSubtree) {
        Oid = _oid;
        Critical = true;

        var rawData = new List<Byte>();
        if (permittedSubtree != null) {
            _permittedSubtree.AddRange(encodeAltNames(permittedSubtree, rawData, 0xa0));
        }
        if (excludedSubtree != null) {
            _excludedSubtree.AddRange(encodeAltNames(excludedSubtree, rawData, 0xa1));
        }
        RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    void m_decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        asn.MoveNext();
        do {
            if (asn.PayloadLength > 0) {
                switch (asn.Tag) {
                    case 0xa0: _permittedSubtree.AddRange(decodeNamesFromAsn(asn.GetTagRawData())); break;
                    case 0xa1: _excludedSubtree.AddRange(decodeNamesFromAsn(asn.GetTagRawData())); break;
                }
            }
        } while (asn.MoveNextSibling());
    }

    static X509AlternativeNameCollection encodeAltNames(X509AlternativeNameCollection permittedSubtree, List<Byte> rawData, Byte tag) {
        var altNames = new X509AlternativeNameCollection();
        var tempRawData = new List<Byte>();
        foreach (X509AlternativeName name in permittedSubtree
                     .Where(x => x.Type != X509AlternativeNamesEnum.RegisteredId)) {
            altNames.Add(name);
            tempRawData.AddRange(Asn1Utils.Encode(name.RawData, 48));
        }
        rawData.AddRange(Asn1Utils.Encode(tempRawData.ToArray(), tag));

        return altNames;
    }
    static X509AlternativeNameCollection decodeNamesFromAsn(Byte[] rawData) {
        var altNames = new X509AlternativeNameCollection();
        var asn = new Asn1Reader(rawData);
        asn.MoveNext();
        do {
            altNames.Add(new X509AlternativeName(asn.GetPayload()));
        } while (asn.MoveNextSibling());

        return altNames;
    }
}