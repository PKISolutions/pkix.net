using System;
using System.Collections.Generic;
using System.Reflection;
using CERTCLILib;

namespace SysadminsLV.PKI.Dcom.Implementations {
    /// <summary>
    /// Represents a Windows implementation of <see cref="ICertConfigEntryD"/> interface.
    /// </summary>
    public class CertConfigEntryD : ICertConfigEntryD {
        readonly List<ICertConfigEnrollEndpointD> _webUriList = new();

        const String CONFIG_COMMONNAME           = "CommonName";
        const String CONFIG_ORGUNIT              = "OrgUnit";
        const String CONFIG_ORGANIZATION         = "Organization";
        const String CONFIG_LOCALITY             = "Locality";
        const String CONFIG_STATE                = "State";
        const String CONFIG_COUNTRY              = "Country";
        const String CONFIG_CONFIG               = "Config";
        const String CONFIG_EXCHANGECERTIFICATE  = "ExchangeCertificate";
        const String CONFIG_SIGNATURECERTIFICATE = "SignatureCertificate";
        const String CONFIG_DESCRIPTION          = "Description";
        const String CONFIG_COMMENT              = "Comment"; // obsolete: use Description
        const String CONFIG_SERVER               = "Server";
        const String CONFIG_AUTHORITY            = "Authority";
        const String CONFIG_SANITIZEDNAME        = "SanitizedName";
        const String CONFIG_SHORTNAME            = "ShortName";
        const String CONFIG_SANITIZEDSHORTNAME   = "SanitizedShortName";
        const String CONFIG_FLAGS                = "Flags";
        const String CONFIG_WEBENROLLMENTSERVERS = "WebEnrollmentServers";

        internal CertConfigEntryD(ICertConfig2 certConfig) {
            foreach (FieldInfo fi in typeof(CertConfigEntryD).GetFields(BindingFlags.NonPublic | BindingFlags.Static)) {
                if (!fi.IsLiteral || fi.IsInitOnly) {
                    continue;
                }
                String constValue = fi.GetRawConstantValue() as String;
                Object value;
                try {
                    value = certConfig.GetField(constValue);
                } catch {
                    continue;
                }

                switch (constValue) {
                    case CONFIG_COMMONNAME:
                        CommonName = (String)value;
                        break;
                    case CONFIG_AUTHORITY:
                        DisplayName = (String)value;
                        break;
                    case CONFIG_DESCRIPTION:
                        Description = (String)value;
                        break;
                    case CONFIG_ORGUNIT:
                        OrganizationUnit = (String)value;
                        break;
                    case CONFIG_ORGANIZATION:
                        Organization = (String)value;
                        break;
                    case CONFIG_LOCALITY:
                        Locality = (String)value;
                        break;
                    case CONFIG_STATE:
                        StateProvince = (String)value;
                        break;
                    case CONFIG_COUNTRY:
                        Country = (String)value;
                        break;
                    case CONFIG_CONFIG:
                        ConfigString = (String)value;
                        break;
                    case CONFIG_SERVER:
                        ComputerName = (String)value;
                        break;
                    case CONFIG_SANITIZEDNAME:
                        SanitizedName = (String)value;
                        break;
                    case CONFIG_SHORTNAME:
                        ShortName = (String)value;
                        break;
                    case CONFIG_SANITIZEDSHORTNAME:
                        SanitizedShortName = (String)value;
                        break;
                    case CONFIG_FLAGS:
                        Flags = (CertConfigLocation)Convert.ToInt32(value);
                        break;
                    case CONFIG_WEBENROLLMENTSERVERS:
                        String[] uriArray = ((String)value)?.Split(new[] { "\n\n" }, StringSplitOptions.None);
                        if (uriArray == null) {
                            break;
                        }

                        foreach (String dsUri in uriArray) {
                            try {
                                _webUriList.Add(new CertConfigEnrollEndpointD(dsUri));
                            } catch { }
                        }
                        break;
                }
            }
        }

        /// <inheritdoc />
        public String ComputerName { get; }
        /// <inheritdoc />
        public String CommonName { get; }
        /// <inheritdoc />
        public String DisplayName { get; }
        /// <inheritdoc />
        public String Description { get; }
        /// <inheritdoc />
        public String OrganizationUnit { get; }
        /// <inheritdoc />
        public String Organization { get; }
        /// <inheritdoc />
        public String StateProvince { get; }
        /// <inheritdoc />
        public String Locality { get; }
        /// <inheritdoc />
        public String Country { get; }
        /// <inheritdoc />
        public String ConfigString { get; }
        /// <inheritdoc />
        public CertConfigLocation Flags { get; }
        /// <inheritdoc />
        public String SanitizedName { get; }
        /// <inheritdoc />
        public String ShortName { get; }
        /// <inheritdoc />
        public String SanitizedShortName { get; }
        /// <inheritdoc />
        public ICertConfigEnrollEndpointD[] WebEnrollmentServers => _webUriList.ToArray();
    }
}