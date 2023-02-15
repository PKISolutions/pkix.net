using System;
using System.Text.RegularExpressions;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents Certification Authority object with defined certificate revocation list validity settings.
    /// </summary>
    public class CertSrvCrlPeriodConfig : CertSrvConfig {
        String basePeriod, deltaPeriod, baseOverlap, deltaOverlap;
        Int32 baseUnits, baseOverlapUnits, deltaUnits, deltaOverlapUnits;

        public CertSrvCrlPeriodConfig(String computerName) : base(computerName) {
            ConfigManager.SetRootNode(true);
            initialize();
        }

        /// <summary>
        /// Gets or sets Base CRL validity period.
        /// </summary>
        public String BaseCRL {
            get => $"{baseUnits} {basePeriod}";
            set => validate($"{baseUnits} {basePeriod}", value, "Base");
        }
        /// <summary>
        /// Gets or sets Base CRL validity extension after new Base CRL is issued.
        /// </summary>
        public String BaseCRLOverlap {
            get => $"{baseOverlapUnits} {baseOverlap}";
            set => validate($"{baseOverlapUnits} {baseOverlap}", value, "BaseOverlap");
        }
        /// <summary>
        /// Gets or sets Delta CRL validity period.
        /// </summary>
        public String DeltaCRL {
            get => $"{deltaUnits} {deltaPeriod}";
            set => validate($"{deltaUnits} {deltaPeriod}", value, "Delta");
        }
        /// <summary>
        /// Gets or sets Base CRL validity extension after new Delta CRL is issued.
        /// </summary>
        public String DeltaCRLOverlap {
            get => $"{deltaOverlapUnits} {deltaOverlap}";
            set => validate($"{deltaOverlapUnits} {deltaOverlap}", value, "DeltaOverlap");
        }

        protected override void OnCommit() {
            ConfigEntries.Add(new RegConfigEntry(ACTIVE_CRLPERIODCOUNT, baseUnits));
            ConfigEntries.Add(new RegConfigEntry(ACTIVE_CRLPERIODSTRING, basePeriod));
            ConfigEntries.Add(new RegConfigEntry(ACTIVE_CRLOVERLAPPERIODCOUNT, baseOverlapUnits));
            ConfigEntries.Add(new RegConfigEntry(ACTIVE_CRLOVERLAPPERIODSTRING, baseOverlap));
            ConfigEntries.Add(new RegConfigEntry(ACTIVE_CRLDELTAPERIODCOUNT, deltaUnits));
            ConfigEntries.Add(new RegConfigEntry(ACTIVE_CRLDELTAPERIODSTRING, deltaPeriod));
            ConfigEntries.Add(new RegConfigEntry(ACTIVE_CRLDELTAOVERLAPPERIODCOUNT, deltaOverlapUnits));
            ConfigEntries.Add(new RegConfigEntry(ACTIVE_CRLDELTAOVERLAPPERIODSTRING, deltaOverlap));
        }

        void initialize() {
            baseUnits = ConfigManager.GetNumericEntry(ACTIVE_CRLPERIODCOUNT);
            basePeriod = ConfigManager.GetStringEntry(ACTIVE_CRLPERIODSTRING);
            baseOverlapUnits = ConfigManager.GetNumericEntry(ACTIVE_CRLOVERLAPPERIODCOUNT);
            baseOverlap = ConfigManager.GetStringEntry(ACTIVE_CRLOVERLAPPERIODSTRING);

            deltaUnits = ConfigManager.GetNumericEntry(ACTIVE_CRLDELTAPERIODCOUNT);
            deltaPeriod = ConfigManager.GetStringEntry(ACTIVE_CRLDELTAPERIODSTRING);
            deltaOverlapUnits = ConfigManager.GetNumericEntry(ACTIVE_CRLDELTAOVERLAPPERIODCOUNT);
            deltaOverlap = ConfigManager.GetStringEntry(ACTIVE_CRLDELTAOVERLAPPERIODSTRING);
        }

        void validate(String oldValidity, String newValidity, String source) {
            if (newValidity != oldValidity) {
                Regex regex = new Regex(@"^(\d+)\s(hours|days|weeks|months|years)");
                Match match = regex.Match(newValidity.ToLower());
                if (match.Success) {
                    switch (source) {
                        case "Base":
                            baseUnits = Convert.ToInt32(match.Groups[1].Value);
                            basePeriod = match.Groups[2].Value.ToLower();
                            break;
                        case "BaseOverlap":
                            baseOverlapUnits = Convert.ToInt32(match.Groups[1].Value);
                            baseOverlap = match.Groups[2].Value.ToLower();
                            break;
                        case "Delta":
                            deltaUnits = Convert.ToInt32(match.Groups[1].Value);
                            deltaPeriod = match.Groups[2].Value.ToLower();
                            break;
                        case "DeltaOverlap":
                            deltaOverlapUnits = Convert.ToInt32(match.Groups[1].Value);
                            deltaOverlap = match.Groups[2].Value.ToLower();
                            break;
                    }
                    IsModified = true;
                } else { throw new FormatException(); }
            }
        }
    }
}