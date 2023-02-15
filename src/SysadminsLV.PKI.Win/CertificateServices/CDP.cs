using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace PKI.CertificateServices {
	/// <summary>
	/// Represents CRLDistributionPoint URL object. An object contains URL information and URL publication settings.
	/// </summary>
	/// <threadsafety static="true" instance="false"/>
	public class CDP {
		/// <summary>Initializes a new instance of the <see cref="CDP">CDP</see> class using URL string.</summary>
		/// <param name="regUri">An URL that is formatted as follows: Flags:protocol/ActualURL/options.
		/// See <see cref="RegURI">RegURI</see> property for variable replacement tokens
		/// and <see cref="Flags">Flags</see> property for detailed information about publication Flags.</param>
		/// <exception cref="ArgumentNullException">The <strong>regUri</strong> parameter is null or empty.</exception>
		/// <exception cref="FormatException">The string in the <strong>regUri</strong> parameter does not match required pattern.</exception>
		/// <remarks>
		/// <p>Only absolute (local), UNC paths and LDAP:// URLs are supported for CRL file publishing.</p>
		/// <p>Only LDAP:// and HTTP:// URLs are supported for CRL file retrieval.</p>
		/// </remarks>
		public CDP(String regUri) {
			if (String.IsNullOrEmpty(regUri)) { throw new ArgumentNullException(nameof(regUri)); }
			RegURI = regUri;
			m_initialize();
		}

		/// <summary>
		/// Gets an URL that is formatted as follows: Flags:protocol/ActualURL/options.
		/// <p>for example, an URL can be: 3:http://pki.company.com/CRL/mycacrl.crl%8%9.crl </p>
		/// See <strong>Remarks</strong> for detailed URL structure.
		/// </summary>
		/// <remarks>The following replacement tokens are defined for CDP URL variables:
		/// <p>%1 - &lt;ServerDNSName&gt; (The DNS name of the certification authority server).</p>
		/// <p>%2 - &lt;ServerShortName&gt; (The NetBIOS name of the certification authority server).</p>
		/// <p>%3 - &lt;CaName&gt; (The name of the certification authority).</p>
		/// <p>%6 - &lt;ConfigurationContainer&gt; (The location of the Configuration container in Active Directory).</p>
		/// <p>%7 - &lt;CATruncatedName&gt; (The "sanitized" name of the certification authority, truncated to 32 characters with a hash on the end).</p>
		/// <p>%8 - &lt;CRLNameSuffix&gt; (Inserts a name suffix at the end of the file name when publishing a CRL to a file or URL location).</p>
		/// <p>%9 - &lt;DeltaCRLAllowed&gt; (When a delta CRL is published, this replaces the CRLNameSuffix with a separate suffix to distinguish the delta CRL).</p>
		/// <p>%10 - &lt;CDPObjectClass&gt; (The object class identifier for CRL distribution points, used when publishing to an LDAP URL).</p>
		/// <p>%11 - &lt;CAObjectClass&gt; - (The object class identifier for a certification authority, used when publishing to an LDAP URL).</p>
		/// <p>See <see cref="Flags">Flags</see> property for flag definitions.</p>
		/// </remarks>
		public String RegURI { get; }
		/// <summary>
		/// Gets an URL representation that is shown in Certification Authority MMC snap-in Extensions tab. See <see cref="RegURI">RegURI</see> property
		/// description for detailed variable token replacement rules.</summary>
		public String ConfigURI { get; private set; }
		/// <summary>
		/// Gets the protocol scheme used by this object.
		/// </summary>
		public UrlProtocolSchemes UrlScheme { get; private set; }
		/// <summary>
		/// Gets an array of projected URIs with expanded (resolved) variables.
		/// </summary>
		/// <remarks>This property is populated when this object is added to a <see cref="CRLDistributionPoint"/> object.</remarks>
		public String[] ProjectedURI { get; internal set; }
		/// <summary>
		/// Gets URL publication Flags. The following Flags (or combination) may be used:
		/// <p>1 - Publish CRLs to this location.</p>
		/// <p>2 - Include in all issued certificates CRL Distribution Points extension.</p>
		/// <p>4 - Include in CRLs. Clients use this to find delta CRL locations.</p>
		/// <p>8 - Include in the CDP extension of CRLs.</p>
		/// <p>64 - Publish delta CRLs to this location. Specifies where to publish in AD DS when publishing to LDAP URLs.</p>
		/// <p>128 - Include in the IDP extension of issued CRLs.</p>
		/// </summary>
		public Int16[] Flags { get; private set; }
		/// <summary>
		/// Gets True if provided URL is configured to publish CRLs to this location.
		/// </summary>
		/// <remarks>Only absolute (local), UNC and LDAP:// paths are supported.</remarks>
		public Boolean CRLPublish { get; private set; }
		/// <summary>
		/// Gets True if provided URL is configured to publish Delta CRLs to this location.
		/// </summary>
		/// <remarks>Only absolute (local), UNC and LDAP:// paths are supported.</remarks>
		public Boolean DeltaCRLPublish { get; private set; }
		/// <summary>
		/// Gets True if provided URL is configured to publish specified URL to all issued certificates' CDP extension.
		/// </summary>
		/// <remarks>Only HTTP:// and LDAP:// paths are supported.</remarks>
		public Boolean AddToCertCDP { get; private set; }
		/// <summary>
		/// Gets True if provided URL is configured to publish specified URL Base CRL CDP extension.
		/// This extension is used to locate Delta CRL locations.
		/// </summary>
		/// <remarks>Only HTTP:// and LDAP:// paths are supported.</remarks>
		public Boolean AddToFreshestCRL { get; private set; }
		/// <summary>
		/// Gets True if provided URL is configured to publish provided URL to CRLs.
		/// </summary>
		/// <remarks>Only LDAP:// paths are supported.</remarks>
		public Boolean AddToCrlcdp { get; private set; }
		/// <summary>
		/// Gets True if provided URL is configured to publish CRLs to CRLs' IDP (Issuing Distribution Point) extension.
		/// </summary>
		/// <remarks>Only HTTP:// and LDAP:// paths are supported.</remarks>
		public Boolean IDP { get; private set; }
		
		void m_initialize() {
			Regex regex = new Regex(@"^\d+");
			Match match = regex.Match(RegURI);
			if (match.Success) {
				Int16 matches = Convert.ToInt16(match.Value);
				Int16[] options = { 1, 2, 4, 8, 64, 128 };
				List<Int16> validoptions = options.Where(option => (matches & option) != 0).ToList();
				Flags = validoptions.ToArray();
				foreach (Int16 option in validoptions) {
					switch (option) {
						case 1: CRLPublish = true; break;
						case 2: AddToCertCDP = true; break;
						case 4: AddToFreshestCRL = true; break;
						case 8: AddToCrlcdp = true; break;
						case 64: DeltaCRLPublish = true; break;
						case 128: IDP = true; break;
						default: throw new Exception("Invalid publishing Flags.");
					}
				}
			} else { throw new FormatException(); }
			ConfigURI = RegURI.Replace("%11", "<CAObjectClass>");
			ConfigURI = ConfigURI.Replace("%10", "<CDPObjectClass>");
			ConfigURI = ConfigURI.Replace("%1", "<ServerDNSName>");
			ConfigURI = ConfigURI.Replace("%2", "<ServerShortName>");
			ConfigURI = ConfigURI.Replace("%3", "<CaName>");
			ConfigURI = ConfigURI.Replace("%6", "<ConfigurationContainer>");
			ConfigURI = ConfigURI.Replace("%7", "<CATruncatedName>");
			ConfigURI = ConfigURI.Replace("%8", "<CRLNameSuffix>");
			ConfigURI = ConfigURI.Replace("%9", "<DeltaCRLAllowed>");
			getUrlScheme();
		}
		void getUrlScheme() {
			Regex regex = new Regex(@"([a-z]:\\(?:[^\\:]+\\)*(?:[^:\\]+\.\w+))");
			if (regex.IsMatch(RegURI)) {
				UrlScheme = UrlProtocolSchemes.Local;
			} else if (RegURI.ToLower().Contains("file://") || RegURI.Contains(@"\\")) {
				UrlScheme = UrlProtocolSchemes.UNC;
			} else if (RegURI.ToLower().Contains("http://")) {
				UrlScheme = UrlProtocolSchemes.HTTP;
			} else if (RegURI.ToLower().Contains("ldap://")) {
				UrlScheme = UrlProtocolSchemes.LDAP;
			} else {
				UrlScheme = UrlProtocolSchemes.Unknown;
			}
		}
		/// <summary>
		/// Returns a string representation of the current CDP object. (Overrides Object.ToString().)
		/// </summary>
		/// <returns>A string representation of the current CDP object.</returns>
		public override String ToString() {
			return ConfigURI;
		}
	}
}
