namespace PKI.Utils {
	/// <summary>
	/// Contains values that represent error status severity.
	/// </summary>
	public enum ErrorSeverity {
		/// <summary>
		/// The status is not available.
		/// </summary>
		None = 0,
		/// <summary>
		/// The status is valid.
		/// </summary>
		Ok = 1,
		/// <summary>
		/// The status has one or more non-critical issues.
		/// </summary>
		Warning = 2,
		/// <summary>
		/// The status has one or more critical issues.
		/// </summary>
		Error = 3
	}
}
