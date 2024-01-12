using System;

namespace SysadminsLV.PKI.Management.CertificateServices;
/// <summary>
/// Represents AD CS Certification Authority (CA) Authority Information Access (AIA) extension configuration.
/// </summary>
public sealed class CertSrvAiaConfig : CertSrvCdpAiaConfig<CertSrvAiaUrlEntry> {

    /// <summary>
    /// Initializes a new instance of <strong>CertSrvAiaConfig</strong> class from CA host name.
    /// </summary>
    /// <param name="computerName">CA host name.</param>
    public CertSrvAiaConfig(String computerName) : base(computerName, ACTIVE_CACERTPUBLICATIONURLS) {
        initialize();
    }

    /// <summary>
    /// Gets a read-only collection of Authority Information Access config URLs.
    /// </summary>
    public CertSrvAiaUrlCollection Entries => new(InternalEntries);

    void initialize() {
        String[] regEntries = ConfigManager.GetMultiStringEntry(ACTIVE_CACERTPUBLICATIONURLS);
        foreach (String regEntry in regEntries) {
            InternalEntries.Add(CertSrvAiaUrlEntry.FromRegUri(regEntry));
        }
    }
}
