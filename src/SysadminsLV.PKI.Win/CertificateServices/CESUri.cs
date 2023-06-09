using System;
using PKI.Enrollment.Policy;

namespace PKI.CertificateServices;
/// <summary>
/// Represents Certificate Enrollment Web Services (CES) URL object.
/// </summary>
public class CESUri {
    //internal String dn;

    /// <param name="uri">Certificate Enrollment Web Services (CES) URL.
    /// </param>
    /// <param name="authentication">Specifies the authentication type supported by the URL.</param>
    /// <param name="priority">Specifies a priority for the URL. The lower number means higher priority.</param>
    /// <param name="renewalOnly">Specifies whether a service supports only renewal operations
    /// (do not support initial certificate enrollment).</param>
    /// <exception cref="ArgumentNullException">The string in the <strong>uri</strong> parameter is null or empty.</exception>
    public CESUri(String uri, PolicyAuthenticationEnum authentication, Int32 priority, Boolean renewalOnly) {
        if (String.IsNullOrEmpty(uri)) { throw new ArgumentNullException(nameof(uri)); }
        m_initialize2(uri, authentication, priority, renewalOnly);
    }

    internal CESUri(String uri, String name) {
        m_initialize(uri, name);
    }

    /// <summary>
    /// Gets the display name of the Certification Authority (sanitized characters are decoded to textual characters).
    /// </summary>
    public String DisplayName { get; set; }
    /// <summary>
    /// Gets URL priority. Lesser number means higher priority.
    /// </summary>
    public Int32 Priority { get; set; }
    /// <summary>
    /// Gets authentication type. The possible values are:
    /// <list type="bullet">
    /// <item><strong>Anonymous</strong> - not used.</item>
    /// <item><strong>Kerberos</strong> - default.</item>
    /// <item><strong>User name and user password</strong></item>
    /// <item><strong>Client certificate</strong></item>
    /// </list>
    /// </summary>
    public PolicyAuthenticationEnum Authentication { get; private set; }
    /// <summary>
    /// Indicates whether the current CES URL can be used for certificate renewal only. If the property is set to
    /// <strong>True</strong>, then this URL cannot be used for initial certificate enrollment and can be used only to renew
    /// existing certificates. If the property is set to <strong>False</strong>, client can use this URL for initial
    /// certificate enrollment and existing certificate renewal.
    /// </summary>
    public Boolean RenewalOnly { get; set; }
    /// <summary>
    /// Gets Enrollment Services location.
    /// </summary>
    public Uri Uri { get; set; }

    void m_initialize(String uri, String name = "") {
        String[] strings = uri.Split(new[] { '\n' }, StringSplitOptions.None);
        Priority = Convert.ToInt32(strings[0]);
        Authentication = (PolicyAuthenticationEnum)Convert.ToInt32(strings[1]);
        RenewalOnly = Convert.ToBoolean(Byte.Parse(strings[2]));
        Uri = new Uri(strings[3].Replace("\0", String.Empty));
        DisplayName = name;
    }
    void m_initialize2(String uri, PolicyAuthenticationEnum authentication, Int32 priority, Boolean renewalOnly) {
        Uri = new Uri(uri);
        Priority = priority;
        Authentication = authentication;
        RenewalOnly = renewalOnly;
    }

    /// <summary>
    /// Displays Certificate Enrollment Service's URL in text format.
    /// </summary>
    /// <returns>The URL information.</returns>
    public override String ToString() {
        return Uri.OriginalString;
    }
}
