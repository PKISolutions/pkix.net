using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.ADCS.CertificateTemplates;
/// <summary>
/// This class represents certificate template cryptography settings.
/// </summary>
public class CryptographyTemplateSettings {
    readonly List<String> _provList = new();

    internal CryptographyTemplateSettings(IAdcsCertificateTemplate template) {
        _provList.AddRange(template.CryptSupportedProviders);
        KeyAlgorithm = new Oid(template.CryptPublicKeyAlgorithm);
        HashAlgorithm = new Oid(template.CryptHashAlgorithm);
        MinimalKeyLength = template.CryptPublicKeyLength;
        PrivateKeyFlags = template.CryptPrivateKeyFlags;
        KeySpec = template.CryptKeySpec;
        if (template.ExtendedProperties.ContainsKey("PrivateKeySDDL")) {
            PrivateKeySecuritySDDL = template.ExtendedProperties["PrivateKeySddl"].ToString();
        }
    }

    /// <summary>
    /// Gets or sets a list of cryptographic service providers (CSPs) that are used to create the private key and public key.
    /// If the property is null, a client may use any CSP installed on the client system.
    /// </summary>
    public String[] ProviderList => _provList.ToArray();
    /// <summary>
    /// Gets or sets key algorithm required by the certificate template.
    /// </summary>
    public Oid KeyAlgorithm { get; }
    /// <summary>
    /// Gets or sets hash algorithm is used to sign request required by the certificate template.
    /// </summary>
    public Oid HashAlgorithm { get; }
    /// <summary>
    /// Gets or sets the minimum size, in bits, of the public key that the client should create to obtain a certificate based
    /// on this template.
    /// </summary>
    public Int32 MinimalKeyLength { get; }
    /// <summary>
    /// Gets or sets private key options.
    /// </summary>
    public CertificateTemplatePrivateKeyFlags PrivateKeyFlags { get; }
    /// <summary>
    /// Indicates operations for which the private key can be used.
    /// </summary>
    public X509KeySpecFlags KeySpec { get; }
    /// <summary>
    /// Gets the permissions when a private key is created
    /// </summary>
    public String PrivateKeySecuritySDDL { get; }

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
            foreach (String csp in ProviderList) {
                SB.AppendLine($"     {csp}");
            }
        }
        SB.AppendLine(@$"  Key Algorithm: {KeyAlgorithm.Format(true)}
  Hash Algorithm: {HashAlgorithm.Format(true)}
  Key Length: {MinimalKeyLength}
  Private key options: {PrivateKeyFlags}
  KeySpec: {KeySpec}");
        if (!String.IsNullOrEmpty(PrivateKeySecuritySDDL)) {
            SB.Append($"{nl}  Private key security descriptor: {PrivateKeySecuritySDDL}");
        }
        return SB.ToString().Trim();
    }
}