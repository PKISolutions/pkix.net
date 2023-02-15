namespace PKI.CertificateTemplates {
	/// <summary>
	/// Defines the possible subject types for certificate template.
	/// </summary>
	public enum CertTemplateSubjectType {
		/// <summary>
		/// Enrollment recipient is user entity.
		/// </summary>
		User,
		/// <summary>
		/// Enrollment recipient is computer or device.
		/// </summary>
		Computer,
		/// <summary>
		/// Enrollment recipient is Certification Authority.
		/// </summary>
		CA,
		/// <summary>
		/// Enrollment recipient is Cross-CertificationAuthority.
		/// </summary>
		CrossCA
	}
}