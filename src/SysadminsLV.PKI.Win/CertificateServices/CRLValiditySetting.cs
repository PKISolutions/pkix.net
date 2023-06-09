using System;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateServices;
/// <summary>
/// Represents Certification Authority object with defined certificate revocation list validity settings.
/// </summary>
public class CRLValiditySetting {
    String ConfigString, BasePeriod, DeltaPeriod, BaseOverlap, DeltaOverlap;
    Int32 BaseUnits, BaseOverlapUnits, DeltaUnits, DeltaOverlapUnits;

    /// <param name="certificateAuthority">Specifies an existing <see cref="CertificateAuthority"/> object.</param>
    public CRLValiditySetting(CertificateAuthority certificateAuthority) {
        if (String.IsNullOrEmpty(certificateAuthority.Name)) { throw new UninitializedObjectException(); }
        m_initialize(certificateAuthority);
    }

    /// <summary>
    /// Gets the common name of the Certification Authority in a sanitized form as specified in
    /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
    /// </summary>
    public String Name { get; private set; }
    /// <summary>
    /// Gets the display name of the Certification Authority (sanitized characters are decoded to textual characters).
    /// </summary>
    public String DisplayName { get; private set; }
    /// <summary>
    /// Gets the host fully qualified domain name (FQDN) of the server where Certification Authority is installed.
    /// </summary>
    public String ComputerName { get; private set; }
    /// <summary>
    /// Gets or sets Base CRL validity period.
    /// </summary>
    public String BaseCRL {
        get { return $"{BaseUnits} {BasePeriod}"; }
        set { validate($"{BaseUnits} {BasePeriod}", value, "Base"); }
    }
    /// <summary>
    /// Gets or sets Base CRL validity extension after new Base CRL is issued.
    /// </summary>
    public String BaseCRLOverlap {
        get { return $"{BaseOverlapUnits} {BaseOverlap}"; }
        set { validate($"{BaseOverlapUnits} {BaseOverlap}", value, "BaseOverlap"); }
    }
    /// <summary>
    /// Gets or sets Delta CRL validity period.
    /// </summary>
    public String DeltaCRL {
        get { return $"{DeltaUnits} {DeltaPeriod}"; }
        set { validate($"{DeltaUnits} {DeltaPeriod}", value, "Delta"); }
    }
    /// <summary>
    /// Gets or sets Base CRL validity extension after new Delta CRL is issued.
    /// </summary>
    public String DeltaCRLOverlap {
        get { return $"{DeltaOverlapUnits} {DeltaOverlap}"; }
        set { validate($"{DeltaOverlapUnits} {DeltaOverlap}", value, "DeltaOverlap"); }
    }
    /// <summary>
    /// Returns <strong>True</strong> if the current object is modified after it is created.
    /// </summary>
    public Boolean IsModified { get; private set; }

    void m_initialize(CertificateAuthority certificateAuthority) {
        Name = certificateAuthority.Name;
        DisplayName = certificateAuthority.DisplayName;
        ComputerName = certificateAuthority.ComputerName;
        ConfigString = certificateAuthority.ConfigString;
        if (CryptoRegistry.Ping(ComputerName)) {
            // Base CRL
            BaseUnits = (Int32)CryptoRegistry.GetRReg("CRLPeriodUnits", Name, ComputerName);
            BasePeriod = (String)CryptoRegistry.GetRReg("CRLPeriod", Name, ComputerName);
            // Base CRL overlap
            BaseOverlapUnits = (Int32)CryptoRegistry.GetRReg("CRLOverlapUnits", Name, ComputerName);
            BaseOverlap = (String)CryptoRegistry.GetRReg("CRLOverlapPeriod", Name, ComputerName);
            // Delta CRL
            DeltaUnits = (Int32)CryptoRegistry.GetRReg("CRLDeltaPeriodUnits", Name, ComputerName);
            DeltaPeriod = (String)CryptoRegistry.GetRReg("CRLDeltaPeriod", Name, ComputerName);
            // Delta CRL overlap
            DeltaOverlapUnits = (Int32)CryptoRegistry.GetRReg("CRLDeltaOverlapUnits", Name, ComputerName);
            DeltaOverlap = (String)CryptoRegistry.GetRReg("CRLDeltaOverlapPeriod", Name, ComputerName);
        } else {
            if (certificateAuthority.Ping()) {
                // Base CRL
                BaseUnits = (Int32)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CRLPeriodUnits");
                BasePeriod = (String)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CRLPeriod");
                // Base CRL overlap
                BaseOverlapUnits = (Int32)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CRLOverlapUnits");
                BaseOverlap = (String)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CRLOverlapPeriod");
                // Delta CRL
                DeltaUnits = (Int32)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CRLDeltaPeriodUnits");
                DeltaPeriod = (String)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CRLDeltaPeriod");
                // Delta CRL overlap
                DeltaOverlapUnits = (Int32)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CRLDeltaOverlapUnits");
                DeltaOverlap = (String)CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CRLDeltaOverlapPeriod");
            } else {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), (OfflineSource)3);
                throw e;
            }
        }
    }
    void validate(String oldValidity, String newValidity, String source) {
        if (newValidity != oldValidity) {
            Regex regex = new Regex(@"^(\d+)\s(hours|days|weeks|months|years)");
            Match match = regex.Match(newValidity.ToLower());
            if (match.Success) {
                switch (source) {
                    case "Base":
                        BaseUnits = Convert.ToInt32(match.Groups[1].Value);
                        BasePeriod = match.Groups[2].Value.ToLower();
                        break;
                    case "BaseOverlap":
                        BaseOverlapUnits = Convert.ToInt32(match.Groups[1].Value);
                        BaseOverlap = match.Groups[2].Value.ToLower();
                        break;
                    case "Delta":
                        DeltaUnits = Convert.ToInt32(match.Groups[1].Value);
                        DeltaPeriod = match.Groups[2].Value.ToLower();
                        break;
                    case "DeltaOverlap":
                        DeltaOverlapUnits = Convert.ToInt32(match.Groups[1].Value);
                        DeltaOverlap = match.Groups[2].Value.ToLower();
                        break;
                }
                IsModified = true;
            } else { throw new FormatException(); }
        }
    }

    /// <summary>
    /// Updates CRL (Base and Delta CRL) setting.
    /// </summary>
    /// <param name="restart">
    /// Indiciates whether to restart certificate services to immediately apply changes. Updated settings has no effect until
    /// CA service is restarted.
    /// </param>
    /// <exception cref="UnauthorizedAccessException">
    /// The caller do not have sufficient permissions to make changes in the CA configuration.
    /// </exception>
    /// <exception cref="ServerUnavailableException">
    /// The target CA server could not be contacted via remote registry and RPC protocol.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
    /// and the method returns <strong>False</strong>.
    /// </returns>
    /// <remarks>The caller must have <strong>Administrator</strong> permissions on the target CA server.</remarks>
    public Boolean SetInfo(Boolean restart) {
        if (!IsModified) { return false; }
        if (CryptoRegistry.Ping(ComputerName)) {
            // Base CRL
            CryptoRegistry.SetRReg(BaseUnits, "CRLPeriodUnits", RegistryValueKind.DWord, Name, ComputerName);
            CryptoRegistry.SetRReg(BasePeriod, "CRLPeriod", RegistryValueKind.String, Name, ComputerName);
            // Base CRL overlap
            CryptoRegistry.SetRReg(BaseOverlapUnits, "CRLOverlapUnits", RegistryValueKind.DWord, Name, ComputerName);
            CryptoRegistry.SetRReg(BaseOverlap, "CRLOverlapPeriod", RegistryValueKind.String, Name, ComputerName);
            // Delta CRL
            CryptoRegistry.SetRReg(DeltaUnits, "CRLDeltaPeriodUnits", RegistryValueKind.DWord, Name, ComputerName);
            CryptoRegistry.SetRReg(DeltaPeriod, "CRLDeltaPeriod", RegistryValueKind.String, Name, ComputerName);
            // Delta CRL overlap
            CryptoRegistry.SetRReg(DeltaOverlapUnits, "CRLDeltaOverlapUnits", RegistryValueKind.DWord, Name, ComputerName);
            CryptoRegistry.SetRReg(DeltaOverlap, "CRLDeltaOverlapPeriod", RegistryValueKind.String, Name, ComputerName);
            IsModified = false;
            if (restart) { CertificateAuthority.Restart(ComputerName); }
            return true;
        }
        if (CertificateAuthority.Ping(ComputerName)) {
            // Base CRL
            CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "CRLPeriodUnits", BaseUnits);
            CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "CRLPeriod", BasePeriod);
            // Base CRL overlap
            CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "CRLOverlapUnits", BaseOverlapUnits);
            CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "CRLOverlapPeriod", BaseOverlap);
            // Delta CRL
            CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "CRLDeltaPeriodUnits", DeltaUnits);
            CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "CRLDeltaPeriod", DeltaPeriod);
            // Delta CRL overlap
            CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "CRLDeltaOverlapUnits", DeltaOverlapUnits);
            CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "CRLDeltaOverlapPeriod", DeltaOverlap);
            IsModified = false;
            if (restart) { CertificateAuthority.Restart(ComputerName); }
            return true;
        }
        ServerUnavailableException e = new ServerUnavailableException(DisplayName);
        e.Data.Add(nameof(e.Source), (OfflineSource)3);
        throw e;
    }
}
