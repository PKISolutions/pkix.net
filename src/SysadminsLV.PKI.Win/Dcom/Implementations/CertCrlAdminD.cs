using CERTADMINLib;
using SysadminsLV.PKI.Management.CertificateServices;
using SysadminsLV.PKI.Utils;
using System;

namespace SysadminsLV.PKI.Dcom.Implementations;
/// <summary>
/// Represents a managed implementation of <see cref="ICertCrlAdminD"/> interface.
/// </summary>
public class CertCrlAdminD : ICertCrlAdminD {
    readonly String _configString;

    /// <summary>
    /// Initializes a new instance of <strong>CertCrlAdmin</strong> class from Certification Authority configuration string.
    /// </summary>
    /// <param name="configString">Certification Authority configuration string.</param>
    public CertCrlAdminD(String configString) {
        _configString = configString;
    }

    void publishCRL(AdcsCrlPublishType crlFlags, DateTime? nextUpdate = null) {
        ICertAdmin2 certAdmin = CertAdminFactory.CreateICertAdmin();
        try {
            certAdmin.PublishCRLs(_configString, nextUpdate ?? DateTime.MinValue, (Int32)crlFlags);
        } finally {
            CryptographyUtils.ReleaseCom(certAdmin);
        }
    }

    /// <inheritdoc />
    public void PublishBaseCrl(DateTime? nextUpdate = null) {
        publishCRL(AdcsCrlPublishType.BaseCRL, nextUpdate);
    }
    /// <inheritdoc />
    public void PublishDeltaCrl(DateTime? nextUpdate = null) {
        publishCRL(AdcsCrlPublishType.DeltaCRL, nextUpdate);
    }
    /// <inheritdoc />
    public void PublishAllCrl(DateTime? nextUpdate = null) {
        publishCRL(getEffectivePublishFlags(AdcsCrlPublishType.BaseCRL | AdcsCrlPublishType.DeltaCRL), nextUpdate);
    }
    /// <inheritdoc />
    public void RepublishDistributionPoints() {
        publishCRL(getEffectivePublishFlags(AdcsCrlPublishType.BaseCRL | AdcsCrlPublishType.DeltaCRL | AdcsCrlPublishType.RePublish));
    }
    /// <summary>
    /// Gets effective CRL publish flags based on the CA configuration. If Delta CRL is not enabled, it is removed from the flags.
    /// </summary>
    /// <param name="desiredFlags">Desired CRL publish flags.</param>
    /// <returns>Allowed flags based on CA configuration.</returns>
    AdcsCrlPublishType getEffectivePublishFlags(AdcsCrlPublishType desiredFlags) {
        var certConfigReader = new CertSrvConfigUtil(_configString.Split('\\')[0]);
        certConfigReader.SetRootNode(true);
        Boolean deltaEnabled = certConfigReader.GetNumericEntry("DeltaCRLPeriodUnits") > 0;
        if (!deltaEnabled) {
            return desiredFlags & ~AdcsCrlPublishType.DeltaCRL;
        }
        
        return desiredFlags;
    }
}