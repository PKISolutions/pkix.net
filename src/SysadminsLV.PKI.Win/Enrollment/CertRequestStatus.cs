using PKI.CertificateServices;
using PKI.Exceptions;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace PKI.Enrollment {
	/// <summary>
	/// Represents ICertRequest request status wrapped object.
	/// </summary>
	public class CertRequestStatus {

        /// <summary>
        /// Gets or sets <see cref="CertificateAuthority">CertificateAuthority</see> object.
        /// </summary>
        public CertificateAuthority CertificationAuthority { get; set; }
		/// <summary>
		/// Gets or sets request ID returned by CA server.
		/// </summary>
		public UInt64 RequestID { get; set; }
		/// <summary>
		/// Gets the request status.
		/// </summary>
		public EnrollmentStatusEnum Status { get; set; }
		/// <summary>
		/// If enrollment was successfull, the property contains issued certificate.
		/// </summary>
		public X509Certificate2 Certificate { get; set; }
		/// <summary>
		/// Gets or sets error information for pending or failed request.
		/// </summary>
		public String ErrorInformation { get; set; }

		/// <summary>
		/// Exports certificate contained in the <see cref="Certificate"/> property to a file.
		/// </summary>
		/// <param name="path">Path to a file.</param>
		public void Export(FileInfo path) {
			if (Certificate.Handle.Equals(IntPtr.Zero)) { throw new UninitializedObjectException(); }
			File.WriteAllBytes(path.FullName, Certificate.RawData);
		}
	}
}
