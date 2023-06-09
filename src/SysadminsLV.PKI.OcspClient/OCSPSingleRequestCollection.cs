using System;
using System.Collections.Generic;
using System.Linq;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.OcspClient;

/// <summary>
/// Represents a collection of <see cref="OCSPSingleRequest"/> objects.
/// </summary>
public class OCSPSingleRequestCollection : BasicCollection<OCSPSingleRequest> {

    /// <summary>
    /// Initializes a new instance of the <see cref="OCSPSingleRequestCollection"/> class
    /// without any <see cref="OCSPSingleRequest"/> information.
    /// </summary>
    public OCSPSingleRequestCollection() { }
    /// <summary>
    /// Initializes a new instance of the <see cref="OCSPSingleRequestCollection"/> class from a
    /// collection of <see cref="OCSPSingleRequest"/> objects.
    /// </summary>
    /// <param name="collection"></param>
    public OCSPSingleRequestCollection(IEnumerable<OCSPSingleRequest> collection) : base(collection) { }

    /// <summary>
    /// Gets an <see cref="OCSPSingleRequest"/> object from the <see cref="OCSPSingleRequestCollection"/> object by revoked certificate's
    /// serial number.
    /// </summary>
    /// <param name="serialNumber">A string that represents a <see cref="CertID.SerialNumber">SerialNumber</see>
    /// property.</param>
    /// <remarks>Use this property to retrieve an <see cref="OCSPSingleRequest"/> object from an <see cref="OCSPSingleRequestCollection"/>
    /// object if you know the <see cref="CertID.SerialNumber">SerialNumber</see> value of the <see cref="CertID"/>
    /// object. You can use the <see cref="this[String]"/> property to retrieve an <see cref="OCSPSingleRequest"/> object if you know
    /// its location in the collection</remarks>
    /// <returns>An <see cref="OCSPSingleRequest"/> object.</returns>
    public OCSPSingleRequest this[String serialNumber]
        => InternalList.FirstOrDefault(x => String.Equals(x.CertId.SerialNumber, serialNumber, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Encodes the collection of OCSPSingleResponse to a ASN.1-encoded byte array.
    /// </summary>
    /// <returns>ASN.1-encoded byte array.</returns>
    public Byte[] Encode() {
        if (InternalList.Count > 0) {
            var rawData = new List<Byte>();
            foreach (OCSPSingleRequest item in InternalList) {
                rawData.AddRange(item.Encode());
            }
            return Asn1Utils.Encode(rawData.ToArray(), 48); // requestList
        }

        return new Byte[] { 48, 0 };
    }
}