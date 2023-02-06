using System;
using System.Collections.Generic;
using System.Linq;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a collection of <see cref="X509CertificatePolicy"/> objects.
/// </summary>
public class X509CertificatePolicyCollection : BasicCollection<X509CertificatePolicy> {
    /// <summary>
    /// Adds an <see cref="X509CertificatePolicy"/> object to the <see cref="X509CertificatePolicyCollection"/> object.
    /// </summary>
    /// <remarks>Use this method to add an <see cref="X509CertificatePolicy"/> object to an existing collection at the current location.</remarks>
    /// <param name="entry">The <see cref="X509CertificatePolicy"/> object to add to the collection.</param>
    /// <returns>
    /// The index of the added <see cref="X509CertificatePolicy"/> object.
    /// <para>
    /// If the method return a negative number (-1), then collection already contains a duplicated policy OID.
    /// Duplicated OIDs are not allowed.
    /// </para>
    /// </returns>
    /// <exception cref="AccessViolationException">The collection is closed and is read-only.</exception>
    public override void Add(X509CertificatePolicy entry) {
        if (entry == null) {
            throw new ArgumentNullException(nameof(entry));
        }

        if (InternalList.Any(item => item.PolicyOid.Value == entry.PolicyOid.Value)) {
            return;
        }
        InternalList.Add(entry);
    }
    /// <summary>
    /// Encodes policy collection to a ASN.1-encoded byte array. Encoded byte array represents certificate policies extension value. 
    /// </summary>
    /// <returns>ASN.1-encoded byte array.</returns>
    public Byte[] Encode() {
        var rawData = new List<Byte>();
        foreach (X509CertificatePolicy policy in InternalList) {
            rawData.AddRange(policy.Encode());
        }
        return Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    /// <summary>
    /// Decodes a collection of certificate policies from a ASN.1-encoded byte array.
    /// <para>
    /// Byte array in the <strong>rawData</strong> parameter must represent certificate policies extension value.
    /// </para>
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array that represents certificate policies extension value.</param>
    /// <exception cref="Asn1InvalidTagException">The data in the <strong>rawData</strong> parameter is not valid
    /// extension value.</exception>
    /// <exception cref="ArgumentNullException"><strong>rawData</strong> is null.</exception>
    public void Decode(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        InternalList.Clear();
        var asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        asn.MoveNext();
        do {
            InternalList.Add(new X509CertificatePolicy(asn.GetTagRawData()));
        } while (asn.MoveNextSibling());
    }

    /// <summary>
    /// Gets an <see cref="X509CertificatePolicy"/> object from the <see cref="X509CertificatePolicyCollection"/> object by policy's
    /// OID value or friendly name.
    /// </summary>
    /// <param name="oid">A string that represents a name or the value of specific policy.</param>
    /// <remarks>Use this property to retrieve an <see cref="X509CertificatePolicy"/> object from an <see cref="X509CertificatePolicyCollection"/>
    /// object if you know the OID name or value value of the <see cref="X509CertificatePolicy"/>
    /// object. You can use the <see cref="this[String]"/> property to retrieve an <see cref="X509CertificatePolicy"/> object if you know
    /// its location in the collection</remarks>
    /// <returns>An <see cref="X509CertificatePolicy"/> object.</returns>
    public X509CertificatePolicy this[String oid] {
        get {
            return InternalList.FirstOrDefault(
                x => String.Equals(x.PolicyOid.FriendlyName, oid, StringComparison.CurrentCultureIgnoreCase) || x.PolicyOid.Value == oid);
        }
    }
}