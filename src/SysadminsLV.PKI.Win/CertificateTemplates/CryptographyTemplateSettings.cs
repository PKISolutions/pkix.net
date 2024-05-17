using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace PKI.CertificateTemplates;
/// <summary>
/// This class represents certificate template cryptography settings.
/// </summary>
public class CryptographyTemplateSettings {
    readonly IAdcsCertificateTemplate _template;

    internal CryptographyTemplateSettings(IAdcsCertificateTemplate template) {
        _template = template;
        initialize();
    }

    /// <summary>
    /// Gets or sets a list of cryptographic service providers (CSPs) that are used to create the private key and public key.
    /// If the property is null, a client may use any CSP installed on the client system.
    /// </summary>
    [Obsolete("Use 'ProviderList' member instead.", true)]
    public String[] CSPList => ProviderList;
    /// <summary>
    /// Gets or sets a list of cryptographic service providers (CSPs) that are used to create the private key and public key.
    /// If the property is null, a client may use any CSP installed on the client system.
    /// </summary>
    public String[] ProviderList { get; private set; } = [];
    /// <summary>
    /// Gets or sets key algorithm required by the certificate template.
    /// </summary>
    public Oid KeyAlgorithm { get; private set; }
    /// <summary>
    /// Gets or sets hash algorithm is used to sign request required by the certificate template.
    /// </summary>
    public Oid HashAlgorithm { get; private set; }
    /// <summary>
    /// Gets or sets the minimum size, in bits, of the public key that the client should create to obtain a certificate based
    /// on this template.
    /// </summary>
    public Int32 MinimalKeyLength { get; private set; }
    /// <summary>
    /// Gets or sets private key options.
    /// </summary>
    public PrivateKeyFlags PrivateKeyOptions { get; private set; }
    /// <summary>
    /// Indicates operations for which the private key can be used.
    /// </summary>
    public X509KeySpecFlags KeySpec { get; private set; }
    /// <summary>
    /// Gets key usages allowed by the template.
    /// </summary>
    public X509KeyUsageFlags KeyUsage { get; private set; }
    /// <summary>
    /// Gets key usages for CNG keys.
    /// </summary>
    public CngKeyUsages CNGKeyUsage { get; private set; }
    /// <summary>
    /// Gets the permissions when a private key is created
    /// </summary>
    public String PrivateKeySecuritySDDL { get; private set; }

    void initialize() {
        PrivateKeyOptions = _template.CryptPrivateKeyFlags;
        MinimalKeyLength = _template.CryptPublicKeyLength;
        KeySpec = _template.CryptKeySpec;
        KeyUsage = _template.ExtensionKeyUsages;
        CNGKeyUsage = _template.CryptCngKeyUsages;
        ProviderList = _template.CryptSupportedProviders;
        KeyAlgorithm = new Oid(_template.CryptPublicKeyAlgorithm);
        HashAlgorithm = new Oid(_template.CryptHashAlgorithm);
        PrivateKeySecuritySDDL = _template.CryptPrivateKeySDDL;
    }

    /// <summary>
    /// Gets a textual representation of the certificate template cryptography settings.
    /// </summary>
    /// <returns>A textual representation of the certificate template cryptography settings</returns>
    public override String ToString() {
        String nl = Environment.NewLine;
        var SB = new StringBuilder();
        SB.Append(@"
[Cryptography Settings]
  CSP list: ");
        if (ProviderList == null) {
            SB.AppendLine("Any installed CSP");
        } else {
            SB.Append(nl);
            for (Int32 index = 0; index < ProviderList.Length; index++) {
                String csp = ProviderList[index];
                SB.AppendLine($"     {index}:{csp}");
            }
        }
        SB.AppendLine(@$"  Key Algorithm: {KeyAlgorithm.Format(true)}
  Hash Algorithm: {HashAlgorithm.Format(true)}
  Key Length: {MinimalKeyLength}
  Private key options: {PrivateKeyOptions}
  KeySpec: {KeySpec}
  CNG key usage: {CNGKeyUsage}");
        if (!String.IsNullOrEmpty(PrivateKeySecuritySDDL)) {
            SB.Append($"{nl}  Private key security descriptor: {PrivateKeySecuritySDDL}");
        }
        return SB.ToString().Trim();
    }
}
