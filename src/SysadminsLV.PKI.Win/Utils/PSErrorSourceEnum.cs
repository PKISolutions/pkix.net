namespace PKI.Utils {
	/// <summary>
	/// Contains error source enumerations used in <see href="http://pspki.codeplex.com/">Powershell PKI Module</see>.
	/// </summary>
	public enum PSErrorSourceEnum {
		/// <summary>
		/// </summary>
		DCUnavailable,
		/// <summary>
		/// </summary>
		CAPIUnavailable,
		/// <summary>
		/// </summary>
		CAUnavailable,
		/// <summary>
		/// </summary>
		WmiUnavailable,
		/// <summary>
		/// </summary>
		WmiWriteError,
		/// <summary>
		/// </summary>
		ADKRAUnavailable,
		/// <summary>
		/// </summary>
		ICertAdminUnavailable,
		/// <summary>
		/// </summary>
		NoXchg,
		/// <summary>
		/// </summary>
		NonEnterprise
	}
}
