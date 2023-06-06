using System;
using CERTADMINLib;
using SysadminsLV.PKI.Utils;

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

    void publishCRL(AdcsCrlPublishType crlFlags, DateTime? nexUpdate = null) {
        ICertAdmin2 certAdmin = new CCertAdminClass();
        try {
            certAdmin.PublishCRLs(_configString, nexUpdate ?? DateTime.UtcNow, (Int32)crlFlags);
        } finally {
            CryptographyUtils.ReleaseCom(certAdmin);
        }
    }

    /// <inheritdoc />
    public void PublishBaseCrl(DateTime? nexUpdate = null) {
        publishCRL(AdcsCrlPublishType.BaseCRL, nexUpdate);
    }
    /// <inheritdoc />
    public void PublishDeltaCrl(DateTime? nexUpdate = null) {
        publishCRL(AdcsCrlPublishType.DeltaCRL, nexUpdate);
    }
    /// <inheritdoc />
    public void PublishAllCrl(DateTime? nexUpdate = null) {
        publishCRL(AdcsCrlPublishType.BaseCRL | AdcsCrlPublishType.DeltaCRL, nexUpdate);
    }
    /// <inheritdoc />
    public void RepublishDistributionPoints() {
        publishCRL(AdcsCrlPublishType.BaseCRL | AdcsCrlPublishType.DeltaCRL | AdcsCrlPublishType.RePublish);
    }
}