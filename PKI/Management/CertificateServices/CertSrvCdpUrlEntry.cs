using System;
using System.Text.RegularExpressions;
using PKI.CertificateServices;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a CRL Distribution Point URL object. An object contains URL information and URL publication settings.
    /// </summary>
    /// <threadsafety static="true" instance="false"/>
    public class CertSrvCdpUrlEntry {
        CertSrvCdpPublishFlags flags = CertSrvCdpPublishFlags.None;

        CertSrvCdpUrlEntry(String uri, Boolean isConfigUri, CertSrvCdpPublishFlags publishFlags) {
            if (String.IsNullOrEmpty(uri)) {
                throw new ArgumentNullException(nameof(uri));
            }

            if (isConfigUri) {
                initializeFromConfig(uri, publishFlags);
            } else {
                initializeFromReg(uri);
            }

            getUrlScheme();
        }


        //public String RegURI { get; }
        /// <summary>
        /// Gets an URL representation that is shown in Certification Authority MMC snap-in Extensions tab. See <see cref="RegURI">RegURI</see> property
        /// description for detailed variable token replacement rules.</summary>
        public String Uri { get; private set; }
        /// <summary>
        /// Gets the protocol scheme used by this object.
        /// </summary>
        public UrlProtocolScheme UrlScheme { get; private set; }
        /// <summary>
        /// Gets an array of projected URIs with expanded (resolved) variables.
        /// </summary>
        /// <remarks>This property is populated when this object is added to a <see cref="CRLDistributionPoint"/> object.</remarks>
        public String[] ProjectedURI { get; internal set; }
        /// <summary>
        /// Gets True if provided URL is configured to publish CRLs to this location.
        /// </summary>
        /// <remarks>Only absolute (local), UNC and LDAP:// paths are supported.</remarks>
        public Boolean PublishToServer => (flags & CertSrvCdpPublishFlags.PublishToServer) > 0;
        /// <summary>
        /// Gets True if provided URL is configured to publish Delta CRLs to this location.
        /// </summary>
        /// <remarks>Only absolute (local), UNC and LDAP:// paths are supported.</remarks>
        public Boolean PublishDeltaToServer => (flags & CertSrvCdpPublishFlags.PublishDeltaToServer) > 0;
        /// <summary>
        /// Gets True if provided URL is configured to publish specified URL to all issued certificates' CDP extension.
        /// </summary>
        /// <remarks>Only HTTP:// and LDAP:// paths are supported.</remarks>
        public Boolean AddToCertificateCdp => (flags & CertSrvCdpPublishFlags.AddToCertificateCdp) > 0;
        /// <summary>
        /// Gets True if provided URL is configured to publish specified URL Base CRL CDP extension.
        /// This extension is used to locate Delta CRL locations.
        /// </summary>
        /// <remarks>Only HTTP:// and LDAP:// paths are supported.</remarks>
        public Boolean AddToFreshestCrl => (flags & CertSrvCdpPublishFlags.AddToFreshestCrl) > 0;
        /// <summary>
        /// Gets True if provided URL is configured to publish provided URL to CRLs.
        /// </summary>
        /// <remarks>Only LDAP:// paths are supported.</remarks>
        public Boolean AddToCrlCdp => (flags & CertSrvCdpPublishFlags.AddToCrlCdp) > 0;
        /// <summary>
        /// Gets True if provided URL is configured to publish CRLs to CRLs' IDP (Issuing Distribution Point) extension.
        /// </summary>
        /// <remarks>Only HTTP:// and LDAP:// paths are supported.</remarks>
        public Boolean AddToCrlIdp => (flags & CertSrvCdpPublishFlags.AddToCrlIdp) > 0;

        void initializeFromReg(String regUri) {
            var regex = new Regex(@"(^\d+):(.+)");
            Match match = regex.Match(regUri);
            if (match.Success) {
                Int16 matches = Convert.ToInt16(match.Groups[1].Value);
                flags = (CertSrvCdpPublishFlags)matches;
                Uri = translateRegToConfigVar(match.Groups[2].Value);
            } else {
                throw new FormatException();
            }
        }
        void initializeFromConfig(String configUri, CertSrvCdpPublishFlags publishFlags) {
            Uri = configUri;
            flags = publishFlags;
        }

        static String translateRegToConfigVar(String regVar) {
            return regVar.Replace("%11", "<CAObjectClass>")
                .Replace("%10", "<CDPObjectClass>")
                .Replace("%1", "<ServerDNSName>")
                .Replace("%2", "<ServerShortName>")
                .Replace("%3", "<CaName>")
                .Replace("%6", "<ConfigurationContainer>")
                .Replace("%7", "<CATruncatedName>")
                .Replace("%8", "<CRLNameSuffix>")
                .Replace("%9", "<DeltaCRLAllowed>");
        }
        static String translateConfigToRegVar(String regVar) {
            return regVar.Replace("<CAObjectClass>", "%11")
                .Replace("<CDPObjectClass>", "%10")
                .Replace("<ServerDNSName>", "%1")
                .Replace("<ServerShortName>", "%2")
                .Replace("<CaName>", "%3")
                .Replace("<ConfigurationContainer>", "%6")
                .Replace("<CATruncatedName>", "%7")
                .Replace("<CRLNameSuffix>", "%8")
                .Replace("<DeltaCRLAllowed>", "%9");
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

        /// <inheritdoc />
        public override String ToString() {
            return Uri;
        }

        /// <inheritdoc />
        public override Boolean Equals(Object obj) {
            return !ReferenceEquals(null, obj) && (ReferenceEquals(this, obj) ||
                                                   obj.GetType() == GetType() && Equals((CertSrvCdpUrlEntry) obj));
        }
        protected Boolean Equals(CertSrvCdpUrlEntry other) {
            return String.Equals(Uri, other.Uri, StringComparison.OrdinalIgnoreCase);
        }
        /// <inheritdoc />
        public override Int32 GetHashCode() {
            return StringComparer.OrdinalIgnoreCase.GetHashCode(Uri);
        }

        /// <summary>
        /// Initializes a new instance of <strong>CertSrvCdpUrlEntry</strong> from registry-based URI format.
        /// <para>Gets an URL that is formatted as follows: Flags:protocol/ActualURL/options.</para>
        /// <para>for example, an URL can be: 3:http://pki.company.com/CRL/mycacrl.crl%8%9.crl</para>
        /// <para>See <strong>Remarks</strong> for detailed URL structure.</para>
        /// </summary>
        /// <param name="uri">A registry-based CDP URI.</param>
        /// <exception cref="ArgumentException">The <strong>uri</strong> parameter is null or empty string.</exception>
        /// <exception cref="FormatException">The string in the <strong>uri</strong> parameter does not match required pattern.</exception>
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
        /// </remarks>
        public static CertSrvCdpUrlEntry FromRegUri(String uri) {
            if (String.IsNullOrWhiteSpace(uri)) {
                throw new ArgumentException("'uri' parameter cannot be null or empty string.");
            }

            return new CertSrvCdpUrlEntry(uri, false, CertSrvCdpPublishFlags.None);
        }

        /// <summary>
        /// Initializes a new instance of the <strong>CertSrvCdpUrlEntry</strong> class using configuration URI string
        /// and publish flags.
        /// </summary>
        /// <param name="uri">An URL that is formatted as shown in Certification Authority management console.</param>
        /// <exception cref="ArgumentException">The <strong>uri</strong> parameter is null or empty string.</exception>
        /// <exception cref="FormatException">The string in the <strong>uri</strong> parameter does not match required pattern.</exception>
        /// <remarks>
        /// <p>Only absolute (local), UNC paths and LDAP:// URLs are supported for CRL file publishing.</p>
        /// <p>Only LDAP:// and HTTP:// URLs are supported for CRL file retrieval.</p>
        /// </remarks>
        public static CertSrvCdpUrlEntry FromConfigUri(String uri, CertSrvCdpPublishFlags publishFlags) {
            if (String.IsNullOrWhiteSpace(uri)) {
                throw new ArgumentException("'uri' parameter cannot be null or empty string.");
            }

            return new CertSrvCdpUrlEntry(uri, true, publishFlags);
        }
    }
}
