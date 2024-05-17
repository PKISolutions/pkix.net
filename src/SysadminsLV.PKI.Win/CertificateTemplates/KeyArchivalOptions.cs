using System;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;

namespace PKI.CertificateTemplates;

/// <summary>
/// Represents certificate template key archival settings.
/// </summary>
public class KeyArchivalOptions {
    readonly IAdcsCertificateTemplate _template;

    internal KeyArchivalOptions (IAdcsCertificateTemplate template) {
        _template = template;
        // default encryption algorithm to 3DES
        EncryptionAlgorithm = new Oid(AlgorithmOid.TrippleDES);
        KeyLength = 168;
        initialize();
    }

    /// <summary>
    /// Specifies whether the key archival is required for the template.
    /// </summary>
    public Boolean KeyArchival { get; private set; }
    /// <summary>
    /// Gets the encryption symmetric algorithm.
    /// </summary>
    public Oid EncryptionAlgorithm { get; private set; }
    /// <summary>
    /// Gets symmetric key length
    /// </summary>
    public Int32 KeyLength { get; private set; }

    void initialize() {
        if ((_template.CryptPrivateKeyFlags & PrivateKeyFlags.RequireKeyArchival) != 0) {
            KeyArchival = true;
            if (!String.IsNullOrEmpty(_template.CryptSymmetricAlgorithm)) {
                EncryptionAlgorithm = new Oid(_template.CryptSymmetricAlgorithm);
            }
            if (_template.CryptSymmetricKeyLength != 0) {
                KeyLength = _template.CryptSymmetricKeyLength;
            }
        }
    }

    /// <summary>
    /// Represents the current object in a textual form.
    /// </summary>
    /// <returns>Textual representation of the object.</returns>
    public override String ToString() {
        var SB = new StringBuilder();
        SB.AppendLine($@"
[Key Archival Settings]
  Key archival required: {KeyArchival}");
        if (KeyArchival) {
            SB.AppendLine(@$"  Symmetric algorithm: {EncryptionAlgorithm.FriendlyName}
  Symmetric key length: {KeyLength}");
        }
        return SB.ToString().Trim();
    }
}