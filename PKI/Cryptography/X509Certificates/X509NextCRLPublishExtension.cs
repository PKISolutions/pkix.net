using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Defines the date and time at which the certification authority schedules new CRL publication.
	/// <para>
	/// Unlike <see cref="X509CRL2.NextUpdate">Next Update</see> field in the X.509 certificate revocation list (CRL)
	/// that specifies the ultimate validity of the CRL, this extension provides information when CA schedules CRL
	/// update which may occur prior to CRL expiration. This allows to fetch new CRL timely.
	/// </para>
	/// </summary>
	public sealed class X509NextCRLPublishExtension : X509Extension {
		readonly Oid _oid = new Oid(X509ExtensionOid.NextCRLPublish);

		/// <summary>
		/// Initializes a new instance of the <strong>X509CRLReferenceExtension</strong> class using an
		/// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
		/// </summary>
		/// <param name="encodedPublishTime">The encoded data to use to create the extension.</param>
		/// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
		/// <exception cref="ArgumentException">
		/// The data in the <strong>value</strong> parameter is not valid extension value.
		/// </exception>
		/// <remarks>This extension SHOULD NOT be marked critical.</remarks>
		public X509NextCRLPublishExtension(AsnEncodedData encodedPublishTime, Boolean critical) {
			if (encodedPublishTime == null) { throw new ArgumentNullException(nameof(encodedPublishTime)); }
			if (encodedPublishTime.RawData == null) { throw new ArgumentException("The parameter is incorrect."); }
			Critical = critical;
			Oid = _oid;
			initializeFromRawData(encodedPublishTime.RawData);
		}
		/// <summary>
		/// Initializes a new instance of the <strong>X509CRLReferenceExtension</strong> class using an
		/// <see cref="DateTime"/> object and a value that identifies whether the extension is critical.
		/// </summary>
		/// <param name="publishTime">The encoded data to use to create the extension.</param>
		/// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
		/// <remarks>This extension SHOULD NOT be marked critical.</remarks>
		public X509NextCRLPublishExtension(DateTime publishTime, Boolean critical) {
			Critical = critical;
			Oid = _oid;
			initializeFromDateTime(publishTime);
		}

		/// <summary>
		/// Gets the date and time at which certification authority schedule new CRL publish.
		/// </summary>
		public DateTime NextCRLPublish { get; private set; }

		void initializeFromDateTime(DateTime publishTime) {
			NextCRLPublish = publishTime;
			RawData = Asn1Utils.EncodeDateTime(publishTime.ToUniversalTime());
		}
		void initializeFromRawData(Byte[] rawData) {
			NextCRLPublish = Asn1Utils.DecodeDateTime(rawData).ToLocalTime();
			RawData = rawData;
		}
	}
}
