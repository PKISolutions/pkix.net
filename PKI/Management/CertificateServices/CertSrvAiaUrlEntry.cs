using System;
using System.Text.RegularExpressions;
using PKI.Management.CertificateServices;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents an Authority Information Access URL object. An object contains URL information and URL publication settings.
    /// An URL indicates how clients can obtain presented certificate's issuer certificate, or how to locate authoritative OCSP responder.
    /// These URLs are generally used for certificate chain building purposes to determine whether the presented certificate came from trusted CA.
    /// </summary>
    public sealed class CertSrvAiaUrlEntry : ICertSrvCdpAiaUri {
        CertSrvAiaPublishFlags flags;

        CertSrvAiaUrlEntry(String uri, Boolean isConfigUri, CertSrvAiaPublishFlags publishFlags) {
            if (isConfigUri) {
                initializeFromConfig(uri, publishFlags);
            } else {
                initializeFromReg(uri);
            }

            getUrlScheme();
        }

        /// <summary>Gets an URL representation that is shown in Certification Authority MMC snap-in Extensions tab.</summary>
        public String Uri { get; private set; }
        /// <summary>
        /// Gets the protocol scheme used by this object.
        /// </summary>
        public UrlProtocolScheme UrlScheme { get; private set; }
        /// <summary>
        /// Gets True if specified URL is configured to publish the CRT file to the specified location.
        /// </summary>
        /// <remarks>Only absolute (local), UNC and LDAP:// paths are supported.</remarks>
        public Boolean ServerPublish => (flags & CertSrvAiaPublishFlags.CertPublish) > 0;
        /// <summary>
        /// Gets True if specified URL is configured to include specified URL to all issued certificate's Authority Information Access extension.
        /// </summary>
        /// <remarks>Only HTTP:// and LDAP:// paths are supported.</remarks>
        public Boolean AddToCertificateAia => (flags & CertSrvAiaPublishFlags.AddToCertificateAia) > 0;
        /// <summary>
        /// Gets True if specified URL is configured to include specified URL to all issued certificate's Authority Information Access extension as a OCSP Locator.
        /// </summary>
        /// <remarks>HTTP:// paths are supported.</remarks>
        public Boolean AddToCertificateOcsp => (flags & CertSrvAiaPublishFlags.AddToCertificateOcsp) > 0;

        void initializeFromReg(String regUri) {
            var regex = new Regex(@"(^\d+):(.+)");
            Match match = regex.Match(regUri);
            if (match.Success) {
                Int16 matches = Convert.ToInt16(match.Groups[1].Value);
                flags = (CertSrvAiaPublishFlags)matches;
                Uri = translateRegToConfigVar(match.Groups[2].Value);
            } else {
                throw new FormatException();
            }
        }
        void initializeFromConfig(String configUri, CertSrvAiaPublishFlags publishFlags) {
            Uri = configUri;
            flags = publishFlags;
        }
        static String translateRegToConfigVar(String regVar) {
            return regVar.Replace("%11", "<CAObjectClass>")
                .Replace("%1", "<ServerDNSName>")
                .Replace("%2", "<ServerShortName>")
                .Replace("%3", "<CaName>")
                .Replace("%4", "<CertificateName>")
                .Replace("%6", "<ConfigurationContainer>")
                .Replace("%7", "<CATruncatedName>");
        }
        static String translateConfigToRegVar(String regVar) {
            return regVar.Replace("<CAObjectClass>", "%11")
                .Replace("<ServerDNSName>", "%1")
                .Replace("<ServerShortName>", "%2")
                .Replace("<CaName>", "%3")
                .Replace("<CertificateName>", "%4")
                .Replace("<ConfigurationContainer>", "%6")
                .Replace("<CATruncatedName>", "%7");
        }

        void getUrlScheme() {
            var regex = new Regex(@"([a-z]:\\(?:[^\\:]+\\)*(?:[^:\\]+\.\w+))", RegexOptions.Compiled | RegexOptions.IgnoreCase);
            String uri = Uri.ToLower();
            if (regex.IsMatch(uri)) {
                UrlScheme = UrlProtocolScheme.Local;
            } else if (uri.StartsWith("file://") || uri.StartsWith(@"\\")) {
                UrlScheme = UrlProtocolScheme.UNC;
            } else if (uri.StartsWith("http://") || uri.StartsWith("https://")) {
                UrlScheme = UrlProtocolScheme.HTTP;
            } else if (uri.StartsWith("ldap://")) {
                UrlScheme = UrlProtocolScheme.LDAP;
            } else if (uri.StartsWith("ftp://")) {
                UrlScheme = UrlProtocolScheme.FTP;
            } else {
                UrlScheme = UrlProtocolScheme.Unknown;
            }
        }

        /// <summary>
        /// Gets a registry-based URI from the current object.
        /// </summary>
        /// <returns>A registry-based URI</returns>
        public String GetRegUri() {
            return $"{(Int32)flags}:{translateConfigToRegVar(Uri)}";
        }
        /// <summary>
        /// Returns a bitwise combination of flags enabled for the current object.
        /// </summary>
        /// <returns>Enabled flags.</returns>
        public CertSrvAiaPublishFlags GetPublishFlags() => flags;
        /// <summary>
        /// Returns a string representation of the current AIA object. (Overrides Object.ToString().)
        /// </summary>
        /// <returns>A string representation of the current AIA object.</returns>
        public override String ToString() {
            return Uri;
        }
        /// <inheritdoc />
        public override Boolean Equals(Object obj) {
            return !ReferenceEquals(null, obj) && (ReferenceEquals(this, obj) ||
                                                   obj.GetType() == GetType() && @equals((CertSrvAiaUrlEntry) obj));
        }
        Boolean @equals(CertSrvAiaUrlEntry other) {
            return String.Equals(Uri, other.Uri, StringComparison.OrdinalIgnoreCase);
        }
        /// <inheritdoc />
        public override Int32 GetHashCode() {
            return StringComparer.OrdinalIgnoreCase.GetHashCode(Uri);
        }

        /// <summary>
        /// Gets an URL that is formatted as follows: flags:protocol/ActualURL/options.
        /// <p>for example, an URL can be: 3:http://pki.company.com/AIA/%2_%3%4.crt </p>
        /// See <strong>Remarks</strong> for detailed URL structure.
        /// </summary>
        /// <exception cref="ArgumentNullException">The <strong>uri</strong> parameter is null or empty.</exception>
        /// <exception cref="FormatException">The string in the <strong>uri</strong> parameter does not match required pattern.</exception>
        /// <remarks>The following replacement tokens are defined for AIA URL variables:
        /// <p>%1 -  &lt;ServerDNSName&gt; (The DNS name of the certification authority server).</p>
        /// <p>%2 -  &lt;ServerShortName&gt; (The NetBIOS name of the certification authority server).</p>
        /// <p>%3 -  &lt;CaName&gt; (The name of the certification authority);</p>
        /// <p>%4 -  &lt;CertificateName&gt; (The renewal extension of the certification authority).</p>
        /// <p>%6 -  &lt;ConfigurationContainer&gt; (The location of the Configuration container in Active Directory).</p>
        /// <p>%7 -  &lt;CATruncatedName&gt; (The "sanitized" name of the certification authority, truncated to 32 characters with a hash on the end).</p>
        /// <p>%11 - &lt;CAObjectClass&gt; - (The object class identifier for a certification authority, used when publishing to an LDAP URL).</p>
        /// <p>See <see cref="flags">flags</see> property for flag definitions.</p>
        /// </remarks>
        public static CertSrvAiaUrlEntry FromRegUri(String uri) {
            if (String.IsNullOrWhiteSpace(uri)) {
                throw new ArgumentException("'uri' parameter cannot be null or empty string.");
            }

            return new CertSrvAiaUrlEntry(uri, false, CertSrvAiaPublishFlags.None);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <exception cref="ArgumentNullException">The <strong>uri</strong> parameter is null or empty.</exception>
        /// <param name="uri"></param>
        /// <param name="publishFlags"></param>
        /// <returns></returns>
        /// <remarks>
        /// <p>Only absolute (local), UNC paths and LDAP:// URLs are supported for CRT file publishing.</p>
        /// <p>Only LDAP:// and HTTP:// URLs are supported for CRT file retrieval.</p>
        /// </remarks>
        public static CertSrvAiaUrlEntry FromConfigUri(String uri, CertSrvAiaPublishFlags publishFlags) {
            if (String.IsNullOrWhiteSpace(uri)) {
                throw new ArgumentException("'uri' parameter cannot be null or empty string.");
            }

            return new CertSrvAiaUrlEntry(uri, true, publishFlags);
        }
    }
}
