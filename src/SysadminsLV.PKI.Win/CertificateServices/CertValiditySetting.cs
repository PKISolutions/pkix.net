using System;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using PKI.Exceptions;
using PKI.Utils;

namespace PKI.CertificateServices {
	/// <summary>
	/// Represents Certification Authority object with defined issued certificates maximum validity period.
	/// </summary>
	/// <remarks>These settings are not absolute. Issued certificate validity period is the lesser value of:
	/// <list type="bullet">
	/// <item>Remaining validity of the CA certificate.</item>
	/// <item>ValidityPeriod registry settings (this object implements ValidityPeriod setting).</item>
	/// <item>Validity defined in certificate template (Enterprise CAs only).</item>
	/// <item>Validity period specified in certificate request</item>
	/// </list> 
	/// </remarks>
	public class CertValiditySetting {
		String m_validity, PeriodUnits, ConfigString;
		Int32 Period;

		/// <param name="certificateAuthority">Specifies an existing <see cref="CertificateServices"/> object.</param>
		/// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
		public CertValiditySetting(CertificateAuthority certificateAuthority) {
			if (String.IsNullOrEmpty(certificateAuthority.Name)) { throw new UninitializedObjectException(); }
			m_initialize(certificateAuthority);
		}

		/// <summary>
		/// Gets the common name of the Certification Authority in a sanitized form as specified in
		/// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
		/// </summary>
		public String Name { get; private set; }
		/// <summary>
		/// Gets the display name of the Certification Authority (sanitized characters are decoded to textual characters).
		/// </summary>
		public String DisplayName { get; private set; }
		/// <summary>
		/// Gets the host fully qualified domain name (FQDN) of the server where Certification Authority is installed.
		/// </summary>
		public String ComputerName { get; private set; }
		/// <summary>
		/// Gets or sets the maximum validity period for issued certificates.
		/// <para>New validity period must be set in the following format: "5 years". As for validity period units the following
		/// values are alloved: <strong>hours</strong>, <strong>days</strong>, <strong>weeks</strong>, <strong>months</strong> and
		/// <strong>years</strong>. All unit qualifiers must be specified in plural form.
		/// </para>
		/// </summary>
		/// <exception cref="FormatException">
		/// The string assigned to the property does not match required pattern.
		/// </exception>
		public String ValidityPeriod {
			get { return m_validity; }
			set { set_validity(value.ToLower()); }
		}
		/// <summary>
		/// Indiciates whether the object was modified after it was instantiated.
		/// </summary>
		public Boolean IsModified { get; private set; }

		void m_initialize(CertificateAuthority certificateAuthority) {
			Name = certificateAuthority.Name;
			DisplayName = certificateAuthority.DisplayName;
			ComputerName = certificateAuthority.ComputerName;
			ConfigString = certificateAuthority.ConfigString;
			if (CryptoRegistry.Ping(ComputerName)) {
				m_validity = Convert.ToString((Int32)CryptoRegistry.GetRReg("ValidityPeriodUnits", Name, ComputerName)) + " ";
				m_validity += (String)CryptoRegistry.GetRReg("ValidityPeriod", Name, ComputerName);
			} else {
				if (certificateAuthority.Ping()) {
					m_validity = Convert.ToString((Int32)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "ValidityPeriodUnits"));
					m_validity += (String)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "ValidityPeriod");
				} else {
					ServerUnavailableException e = new ServerUnavailableException(DisplayName);
					e.Data.Add(nameof(e.Source), (OfflineSource)3);
					throw e;
				}
			}
		}
		void set_validity(String validity) {
			if (validity != ValidityPeriod) {
				Regex regex = new Regex(@"^(\d+)\s(hours|days|weeks|months|years)");
				Match match = regex.Match(validity);
				if (match.Success) {
					Period = Convert.ToInt32(match.Groups[1].Value);
					PeriodUnits = match.Groups[2].Value.ToLower();
					m_validity = $"{Period} {PeriodUnits}";
					IsModified = true;
				} else { throw new FormatException(); }
			}
		}

		/// <summary>
		/// Updates issued certificate validity setting. Any issued certificate validity cannot exceed this value.
		/// </summary>
		/// <param name="restart">
		/// Indiciates whether to restart certificate services to immediately apply changes. Updated settings has no effect until
		/// CA service is restarted.
		/// </param>
		/// <exception cref="UnauthorizedAccessException">
		/// The caller do not have sufficient permissions to make changes in the CA configuration.
		/// </exception>
		/// <exception cref="ServerUnavailableException">
		/// The target CA server could not be contacted via remote registry and RPC protocol.
		/// </exception>
		/// <returns>
		/// <strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
		/// and the method returns <strong>False</strong>.
		/// </returns>
		/// <remarks>The caller must have <strong>Administrator</strong> permissions on the target CA server.</remarks>
		public Boolean SetInfo(Boolean restart) {
			if (!IsModified) { return false; }
			if (CryptoRegistry.Ping(ComputerName)) {
				CryptoRegistry.SetRReg(Period, "ValidityPeriodUnits", RegistryValueKind.DWord, Name, ComputerName);
				CryptoRegistry.SetRReg(PeriodUnits, "ValidityPeriod", RegistryValueKind.String, Name, ComputerName);
				IsModified = false;
				if (restart) { CertificateAuthority.Restart(ComputerName); }
				return true;
			}
			if (CertificateAuthority.Ping(ComputerName)) {
				CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "ValidityPeriodUnits", Period);
				CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "ValidityPeriod", PeriodUnits);
				IsModified = false;
				if (restart) { CertificateAuthority.Restart(ComputerName); }
				return true;
			}
			ServerUnavailableException e = new ServerUnavailableException(DisplayName);
			e.Data.Add(nameof(e.Source), (OfflineSource)3);
			throw e;
		}
		/// <summary>
		/// Returns a string representation of the current validity period setting.
		/// </summary>
		/// <returns>A string representation of the current validity period setting.</returns>
		public override String ToString() {
			return $"{DisplayName}: {ValidityPeriod}";
		}
	}
}
