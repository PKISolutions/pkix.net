﻿using System;
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
        publishCRL(AdcsCrlPublishType.BaseCRL | AdcsCrlPublishType.DeltaCRL, nextUpdate);
    }
    /// <inheritdoc />
    public void RepublishDistributionPoints() {
        publishCRL(AdcsCrlPublishType.BaseCRL | AdcsCrlPublishType.DeltaCRL | AdcsCrlPublishType.RePublish);
    }
}