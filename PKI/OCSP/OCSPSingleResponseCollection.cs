using System.Collections.Generic;
using SysadminsLV.PKI;
using SysadminsLV.PKI.OcspClient;

namespace PKI.OCSP {
    /// <summary>
    /// Represents a collection of <see cref="SysadminsLV.PKI.OcspClient.OCSPSingleResponse"/> objects.
    /// </summary>
    public class OCSPSingleResponseCollection : BasicCollection<OCSPSingleResponse> {

        /// <summary>
        /// Initializes a new instance of the <see cref="OCSPSingleResponseCollection"/> class without
        /// any <see cref="SysadminsLV.PKI.OcspClient.OCSPSingleResponse"/> information.
        /// </summary>
        public OCSPSingleResponseCollection() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="OCSPSingleResponseCollection"/> class from an existing
        /// collection of items.
        /// </summary>
        /// <param name="collection">The collection whose elements are copied to the new list.</param>
        public OCSPSingleResponseCollection(IEnumerable<OCSPSingleResponse> collection) : base(collection) { }

        ///// <summary>
        ///// Gets an <see cref="OCSPSingleResponse"/> object from the <see cref="OCSPSingleResponseCollection"/> object by revoked certificate's
        ///// serial number.
        ///// </summary>
        ///// <param name="status">A string that represents a <see cref="OCSPSingleResponse.CertStatus">CertStatus</see>
        ///// property.</param>
        ///// <remarks>Use this property to retrieve an <see cref="OCSPSingleResponse"/> object from an <see cref="OCSPSingleResponseCollection"/>
        ///// object if you know the <see cref="OCSPSingleResponse.CertStatus">Status</see> value of the <see cref="OCSPSingleResponse"/>
        ///// object. You can use the <see cref="this[CertificateStatus]"/> property to retrieve an <see cref="OCSPSingleResponse"/> object if you know
        ///// its location in the collection</remarks>
        ///// <returns>An <see cref="OCSPSingleResponse"/> object.</returns>
        ////public OCSPSingleResponse this[CertificateStatus status] => _list.FirstOrDefault(x => x.CertStatus == status);
    }
}