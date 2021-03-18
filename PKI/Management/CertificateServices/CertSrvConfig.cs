using System;
using System.Collections.Generic;
using System.Linq;
using PKI.CertificateServices;
using PKI.Exceptions;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents base class for Certification Authority configuration. This is abstract class and cannot be instantiated directly.
    /// </summary>
    public abstract class CertSrvConfig {
        /// <summary>
        /// Initializes a new instance of <strong>CertSrvConfig</strong> from a string that contains a computer name where Certification Authority is installed.
        /// </summary>
        /// <param name="computerName">computer name where Certification Authority is installed.</param>
        /// <exception cref="ArgumentException"><strong>computerName</strong> parameter cannot be null or empty string.</exception>
        /// <exception cref="ServerUnavailableException">Certification Authority is not accessible via any supported protocol.</exception>
        protected CertSrvConfig(String computerName) {
            if (String.IsNullOrWhiteSpace(computerName)) {
                throw new ArgumentException(nameof(computerName));
            }

            ComputerName = computerName;
            ConfigManager = new CertSrvConfigUtil(ComputerName);

            if (!ConfigManager.RegistryOnline && !ConfigManager.DcomOnline) {
                var e = new ServerUnavailableException(ComputerName);
                e.Data.Add(nameof(e.Source), OfflineSource.All);

                throw e;
            }
        }

        #region config entry names
        protected const String KEY_CSP                                   = "CSP";
        protected const String KEY_ENCRYPTIONCSP                         = "EncryptionCSP";
        protected const String KEY_EXITMODULES                           = "ExitModules";
        protected const String KEY_POLICYMODULES                         = "PolicyModules";
        protected const String ROOT_ACTIVE                               = "Active";
        protected const String ROOT_DIRECTORY                            = "ConfigurationDirectory";
        protected const String ROOT_DBDIRECTORY                          = "DBDirectory";
        protected const String ROOT_DBLOGDIRECTORY                       = "DBLogDirectory";
        protected const String ROOT_DBSYSDIRECTORY                       = "DBSystemDirectory";
        protected const String ROOT_DBTEMPDIRECTORY                      = "DBTempDirectory";
        protected const String ROOT_DBSESSIONCOUNT                       = "DBSessionCount";
        protected const String ROOT_DBFLAGS                              = "DBFlags";
        protected const String ROOT_DBLASTFULLBACKUP                     = "DBLastFullBackup";
        protected const String ROOT_DBLASTINCREMENTALBACKUP              = "DBLastIncrementalBackup";
        protected const String ROOT_DBLASTRECOVERY                       = "DBLastRecovery";
        protected const String ROOT_WEBCLIENTCAMACHINE                   = "WebClientCAMachine";
        protected const String ROOT_VERSION                              = "Version";
        protected const String ROOT_WEBCLIENTCANAME                      = "WebClientCAName";
        protected const String ROOT_WEBCLIENTCATYPE                      = "WebClientCAType";
        protected const String ROOT_LDAPFLAGS                            = "LDAPFlags";
        protected const String ROOT_CERTSRVDEBUG                         = "Debug";
        protected const String CSP_PROVIDERTYPE                          = "ProviderType";
        protected const String CSP_PROVIDER                              = "Provider";
        protected const String CSP_HASHALGORITHM                         = "HashAlgorithm";
        protected const String CSP_ENCRYPTIONALGORITHM                   = "EncryptionAlgorithm";
        protected const String CSP_MACHINEKEYSET                         = "MachineKeyset";
        protected const String CSP_KEYSIZE                               = "KeySize";
        protected const String CSP_SYMMETRICKEYSIZE                      = "SymmetricKeySize";
        protected const String CSP_CNGPUBLICKEYALGORITHM                 = "CNGPublicKeyAlgorithm";
        protected const String CSP_CNGHASHALGORITHM                      = "CNGHashAlgorithm";
        protected const String CSP_CNGENCRYPTIONALGORITHM                = "CNGEncryptionAlgorithm";
        protected const String CSP_ALTERNATESIGNATUREALGORITHM           = "AlternateSignatureAlgorithm";
        protected const String EXIT_SMTPKEY                              = "SMTP";
        protected const String EXIT_SMTPTEMPLATES                        = "Templates";
        protected const String EXIT_SMTPEVENTFILTER                      = "EventFilter";
        protected const String EXIT_SMTPSERVER                           = "SMTPServer";
        protected const String EXIT_SMTPAUTHENTICATE                     = "SMTPAuthenticate";
        protected const String EXIT_DENIEDKEY                            = "Denied";
        protected const String EXIT_ISSUEDKEY                            = "Issued";
        protected const String EXIT_PENDINGKEY                           = "Pending";
        protected const String EXIT_REVOKEDKEY                           = "Revoked";
        protected const String EXIT_CRLISSUEDKEY                         = "CRLIssued";
        protected const String EXIT_SHUTDOWNKEY                          = "Shutdown";
        protected const String EXIT_STARTUPKEY                           = "Startup";
        protected const String EXIT_IMPORTEDKEY                          = "Imported";
        protected const String EXIT_SMTPFROM                             = "From";
        protected const String EXIT_SMTPTO                               = "To";
        protected const String EXIT_SMTPCC                               = "Cc";
        protected const String EXIT_TITLEFORMAT                          = "Title Format";
        protected const String EXIT_TITLEARG                             = "TitleArg";
        protected const String EXIT_BODYFORMAT                           = "Body Format";
        protected const String EXIT_BODYARG                              = "BodyArg";
        protected const String POLICY_ISSUERCERTURLFLAGS                 = "IssuerCertURLFlags";
        protected const String POLICY_EDITFLAGS                          = "EditFlags";
        protected const String POLICY_UPNMAP                             = "UPNMap";
        protected const String POLICY_SUBJECTALTNAME                     = "SubjectAltName";
        protected const String POLICY_SUBJECTALTNAME2                    = "SubjectAltName2";
        protected const String POLICY_REQUESTDISPOSITION                 = "RequestDisposition";
        protected const String POLICY_CAPATHLENGTH                       = "CAPathLength";
        protected const String POLICY_REVOCATIONTYPE                     = "RevocationType";
        protected const String POLICY_LDAPREVOCATIONCRLURL_OLD           = "LDAPRevocationCRLURL";
        protected const String POLICY_REVOCATIONCRLURL_OLD               = "RevocationCRLURL";
        protected const String POLICY_FTPREVOCATIONCRLURL_OLD            = "FTPRevocationCRLURL";
        protected const String POLICY_FILEREVOCATIONCRLURL_OLD           = "FileRevocationCRLURL";
        protected const String POLICY_REVOCATIONURL                      = "RevocationURL";
        protected const String POLICY_LDAPISSUERCERTURL_OLD              = "LDAPIssuerCertURL";
        protected const String POLICY_ISSUERCERTURL_OLD                  = "IssuerCertURL";
        protected const String POLICY_FTPISSUERCERTURL_OLD               = "FTPIssuerCertURL";
        protected const String POLICY_FILEISSUERCERTURL_OLD              = "FileIssuerCertURL";
        protected const String POLICY_ENABLEREQUESTEXTENSIONLIST         = "EnableRequestExtensionList";
        protected const String POLICY_ENABLEENROLLEEREQUESTEXTENSIONLIST = "EnableEnrolleeRequestExtensionList";
        protected const String POLICY_DISABLEEXTENSIONLIST               = "DisableExtensionList";
        protected const String POLICY_DEFAULTSMIME                       = "DefaultSMIME";
        protected const String ACTIVE_CADESCRIPTION                      = "CADescription";
        protected const String ACTIVE_CACERTHASH                         = "CACertHash";
        protected const String ACTIVE_CASERIALNUMBER                     = "CACertSerialNumber";
        protected const String ACTIVE_CAXCHGCERTHASH                     = "CAXchgCertHash";
        protected const String ACTIVE_KRACERTHASH                        = "KRACertHash";
        protected const String ACTIVE_KRACERTCOUNT                       = "KRACertCount";
        protected const String ACTIVE_KRAFLAGS                           = "KRAFlags";
        protected const String ACTIVE_CATYPE                             = "CAType";
        protected const String ACTIVE_CERTENROLLCOMPATIBLE               = "CertEnrollCompatible";
        protected const String ACTIVE_ENFORCEX500NAMELENGTHS             = "EnforceX500NameLengths";
        protected const String ACTIVE_COMMONNAME                         = "CommonName";
        protected const String ACTIVE_CLOCKSKEWMINUTES                   = "ClockSkewMinutes";
        protected const String ACTIVE_CRLNEXTPUBLISH                     = "CRLNextPublish";
        protected const String ACTIVE_CRLPERIODSTRING                    = "CRLPeriod";
        protected const String ACTIVE_CRLPERIODCOUNT                     = "CRLPeriodUnits";
        protected const String ACTIVE_CRLOVERLAPPERIODSTRING             = "CRLOverlapPeriod";
        protected const String ACTIVE_CRLOVERLAPPERIODCOUNT              = "CRLOverlapUnits";
        protected const String ACTIVE_CRLDELTANEXTPUBLISH                = "CRLDeltaNextPublish";
        protected const String ACTIVE_CRLDELTAPERIODSTRING               = "CRLDeltaPeriod";
        protected const String ACTIVE_CRLDELTAPERIODCOUNT                = "CRLDeltaPeriodUnits";
        protected const String ACTIVE_CRLDELTAOVERLAPPERIODSTRING        = "CRLDeltaOverlapPeriod";
        protected const String ACTIVE_CRLDELTAOVERLAPPERIODCOUNT         = "CRLDeltaOverlapUnits";
        protected const String ACTIVE_CRLPUBLICATIONURLS                 = "CRLPublicationURLs";
        protected const String ACTIVE_CACERTPUBLICATIONURLS              = "CACertPublicationURLs";
        protected const String ACTIVE_CAXCHGVALIDITYPERIODSTRING         = "CAXchgValidityPeriod";
        protected const String ACTIVE_CAXCHGVALIDITYPERIODCOUNT          = "CAXchgValidityPeriodUnits";
        protected const String ACTIVE_CAXCHGOVERLAPPERIODSTRING          = "CAXchgOverlapPeriod";
        protected const String ACTIVE_CAXCHGOVERLAPPERIODCOUNT           = "CAXchgOverlapPeriodUnits";
        protected const String ACTIVE_CRLPATH_OLD                        = "CRLPath";
        protected const String ACTIVE_CRLEDITFLAGS                       = "CRLEditFlags";
        protected const String ACTIVE_CRLFLAGS                           = "CRLFlags";
        protected const String ACTIVE_CRLATTEMPTREPUBLISH                = "CRLAttemptRepublish";
        protected const String ACTIVE_ENABLED                            = "Enabled";
        protected const String ACTIVE_FORCETELETEX                       = "ForceTeletex";
        protected const String ACTIVE_LOGLEVEL                           = "LogLevel";
        protected const String ACTIVE_HIGHSERIAL                         = "HighSerial";
        protected const String ACTIVE_POLICYFLAGS                        = "PolicyFlags";
        protected const String ACTIVE_NAMESEPARATOR                      = "SubjectNameSeparator";
        protected const String ACTIVE_SUBJECTTEMPLATE                    = "SubjectTemplate";
        protected const String ACTIVE_CAUSEDS                            = "UseDS";
        protected const String ACTIVE_VALIDITYPERIODSTRING               = "ValidityPeriod";
        protected const String ACTIVE_VALIDITYPERIODCOUNT                = "ValidityPeriodUnits";
        protected const String ACTIVE_PARENTCAMACHINE                    = "ParentCAMachine";
        protected const String ACTIVE_PARENTCANAME                       = "ParentCAName";
        protected const String ACTIVE_REQUESTFILENAME                    = "RequestFileName";
        protected const String ACTIVE_REQUESTID                          = "RequestId";
        protected const String ACTIVE_REQUESTKEYCONTAINER                = "RequestKeyContainer";
        protected const String ACTIVE_REQUESTKEYINDEX                    = "RequestKeyIndex";
        protected const String ACTIVE_SECUREDATTRIBUTES                  = "SignedAttributes";
        protected const String ACTIVE_CASERVERNAME                       = "CAServerName";
        protected const String ACTIVE_CACERTFILENAME                     = "CACertFileName";
        protected const String ACTIVE_CASECURITY                         = "Security";
        protected const String ACTIVE_AUDITFILTER                        = "AuditFilter";
        protected const String ACTIVE_OFFICERRIGHTS                      = "OfficerRights";
        protected const String ACTIVE_ENROLLMENTAGENTRIGHTS              = "EnrollmentAgentRights";
        protected const String ACTIVE_MAXINCOMINGMESSAGESIZE             = "MaxIncomingMessageSize";
        protected const String ACTIVE_MAXINCOMINGALLOCSIZE               = "MaxIncomingAllocSize";
        protected const String ACTIVE_ROLESEPARATIONENABLED              = "RoleSeparationEnabled";
        protected const String ACTIVE_ALTERNATEPUBLISHDOMAINS            = "AlternatePublishDomains";
        protected const String ACTIVE_SETUPSTATUS                        = "SetupStatus";
        protected const String ACTIVE_INTERFACEFLAGS                     = "InterfaceFlags";
        protected const String ACTIVE_DSCONFIGDN                         = "DSConfigDN";
        protected const String ACTIVE_DSDOMAINDN                         = "DSDomainDN";
        protected const String ACTIVE_VIEWAGEMINUTES                     = "ViewAgeMinutes";
        protected const String ACTIVE_VIEWIDLEMINUTES                    = "ViewIdleMinutes";
        protected const String ACTIVE_USEDEFINEDCACERTINREQ              = "UseDefinedCACertInRequest";
        protected const String ACTIVE_ENABLEDEKUFORDEFINEDCACERT         = "EnabledEKUForDefinedCACert";
        protected const String ACTIVE_EKUOIDSFORPUBLISHEXPIREDCERTINCRL  = "EKUOIDsForPublishExpiredCertInCRL";
        #endregion

        /// <summary>
        /// Gets the certification authority computer name.
        /// </summary>
        public String ComputerName { get; }
        /// <summary>
        /// Indicates whether the object was modified after it was instantiated. This member is set to <strong>False</strong> upon successful changes commit.
        /// </summary>
        public Boolean IsModified { get; protected set; }
        /// <summary>
        /// Gets the CA configuration read/write manager used by implementers to read and write configuration.
        /// </summary>
        protected CertSrvConfigUtil ConfigManager { get; }
        protected List<RegConfigEntry> ConfigEntries { get; } = new List<RegConfigEntry>();

        protected virtual void OnCommit() { }

        /// <summary>
        /// Updates Certification Authority configuration on a server.
        /// </summary>
        /// <param name="restart">
        ///		Indicates whether to restart certificate services to immediately apply changes. Updated settings has no effect
        ///		until CA service is restarted.
        /// </param>
        /// <exception cref="ServerUnavailableException">
        ///		The target CA server could not be contacted via remote registry and RPC protocol.
        /// </exception>
        /// <returns>
        ///		<strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
        ///		and the method returns <strong>False</strong>.
        /// </returns>
        /// <remarks>
        ///		The caller must have <strong>Administrator</strong> permissions on the target CA server.
        /// </remarks>
        public Boolean Commit(Boolean restart) {
            if (!IsModified) {
                return IsModified;
            }

            OnCommit();
            foreach (RegConfigEntry entry in ConfigEntries.Where(x => x.Action == RegConfigEntryAction.Delete)) {
                ConfigManager.SetRootNode(!entry.IsRoot);
                ConfigManager.DeleteEntry(entry.Name, entry.Node);
            }

            foreach (RegConfigEntry entry in ConfigEntries.Where(x => x.Action == RegConfigEntryAction.Write)) {
                ConfigManager.SetRootNode(!entry.IsRoot);
                ConfigManager.SetEntry(entry.Name, entry.Node, entry.Value);
            }

            IsModified = false;
            if (restart) {
                CertificateAuthority.Restart(ComputerName);
            }

            return true;
        }
    }
}