using System;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Management.ActiveDirectory;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateTemplates;

/// <summary>
/// Represents certificate template key archival settings.
/// </summary>
public class KeyArchivalOptions {
    readonly DsPropertyCollection _entry;

    KeyArchivalOptions() {
        // default encryption algorithm to 3DES
        EncryptionAlgorithm = new Oid(AlgorithmOid.TrippleDES);
        KeyLength = 168;
    }

    internal KeyArchivalOptions(DsPropertyCollection Entry) : this() {
        _entry = Entry;
        initializeFromDs();
    }
    internal KeyArchivalOptions (IAdcsCertificateTemplate template) : this() {
        initializeFromCom(template);
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

    void initializeFromDs() {
        if (((Int32)_entry[DsUtils.PropPkiPKeyFlags] & (Int32)PrivateKeyFlags.RequireKeyArchival) != 0) {
            KeyArchival = true;
            String ap = (String)_entry[DsUtils.PropPkiRaAppPolicy];
            if (ap != null && ap.Contains("`")) {
                String[] delimiter = ["`"];
                String[] strings = ap.Split(delimiter, StringSplitOptions.RemoveEmptyEntries);
                for (Int32 index = 0; index < strings.Length; index += 3) {
                    switch (strings[index]) {
                        case DsUtils.PropPkiSymAlgo: EncryptionAlgorithm = new Oid(strings[index + 2]); break;
                        case DsUtils.PropPkiSymLength: KeyLength = Convert.ToInt32(strings[index + 2]); break;
                    }
                }
            }
        }
    }
    void initializeFromCom(IAdcsCertificateTemplate template) {
        PrivateKeyFlags pkFlags = template.CryptPrivateKeyFlags;
        if ((pkFlags & PrivateKeyFlags.RequireKeyArchival) != 0) {
            KeyArchival = true;
            if (!String.IsNullOrEmpty(template.CryptSymmetricAlgorithm)) {
                EncryptionAlgorithm = new Oid(template.CryptSymmetricAlgorithm);
            }
            KeyLength = template.CryptSymmetricKeyLength;
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