using System;
using System.Linq;
using System.Security.Cryptography;
using CERTADMINLib;
using CERTCLILib;

namespace SysadminsLV.PKI.Dcom.Implementations {
    /// <summary>
    /// Represents a Windows-specific implementation of <see cref="ICertPropReaderD"/> interface.
    /// </summary>
    public class CertPropReaderD : ICertPropReaderD {
        readonly String _configString;
        readonly Func<String, Int32, Int32, Int32, Int32, Object> _getCaPropertyFunc;
        const Int32 MAX_INDEX = unchecked((Int32)0xffffffff);

        /// <summary>
        /// Initializes a new instance of <strong>CertPropReaderD</strong> class from a Certification Authority configuration string.
        /// </summary>
        /// <param name="configString">Certification Authority configuration string.</param>
        /// <param name="forceCertAdmin">
        /// <strong>True</strong> to force ICertAdmin implementation which requires extra privileges, otherwise ICertRequest implementation is used.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <strong>configString</strong> parameter is null.
        /// </exception>
        public CertPropReaderD(String configString, Boolean forceCertAdmin) {
            _configString = configString ?? throw new ArgumentNullException(nameof(configString));
            if (forceCertAdmin) {
                _getCaPropertyFunc = new CCertAdminClass().GetCAProperty;
            } else {
                _getCaPropertyFunc = new CCertRequestClass().GetCAProperty;
            }
        }
        Int32 getIntegerProperty(AdcsCAPropertyName propID, Int32 index = 0) {
            return (Int32)_getCaPropertyFunc.Invoke(_configString, (Int32)propID, index, (Int32)AdcsCAPropertyValueType.Long, 0);
        }
        Byte[] getBinaryProperty(AdcsCAPropertyName propID, Int32 index = 0) {
            String value = (String)_getCaPropertyFunc.Invoke(_configString, (Int32)propID, index, (Int32)AdcsCAPropertyValueType.Binary, (Int32)AdcsBinaryFormat.Base64NoHeader);
            return Convert.FromBase64String(value);
        }
        String getStringProperty(AdcsCAPropertyName propID, Int32 index = 0) {
            return (String)_getCaPropertyFunc.Invoke(_configString, (Int32)propID, index, (Int32)AdcsCAPropertyValueType.String, 0);
        }

        #region GetCAProperty
        /// <inheritdoc />
        public String GetFileVersionProperty() {
            return getStringProperty(AdcsCAPropertyName.FileVersion);
        }
        /// <inheritdoc />
        public String GetProductVersionProperty() {
            return getStringProperty(AdcsCAPropertyName.ProductVersion);
        }
        /// <inheritdoc />
        public Int32 GetExitModuleCount() {
            return getIntegerProperty(AdcsCAPropertyName.ExitCount);
        }
        /// <inheritdoc />
        public String GetExitModuleDescription(Int32 index) {
            return getStringProperty(AdcsCAPropertyName.ExitDescription, index);
        }
        /// <inheritdoc />
        public String GetPolicyModuleDescription() {
            return getStringProperty(AdcsCAPropertyName.PolicyDescription);
        }
        /// <inheritdoc />
        public String GetCaName() {
            return getStringProperty(AdcsCAPropertyName.CaName);
        }
        /// <inheritdoc />
        public String GetSanitizedCaName() {
            return getStringProperty(AdcsCAPropertyName.SanitizedCaName);
        }
        /// <inheritdoc />
        public String GetSharedFolderPath() {
            return getStringProperty(AdcsCAPropertyName.SharedFolder);
        }
        /// <inheritdoc />
        public String GetParentCA() {
            return getStringProperty(AdcsCAPropertyName.ParentCa);
        }
        /// <inheritdoc />
        public AdcsPropCaType GetCaType() {
            return (AdcsPropCaType)getIntegerProperty(AdcsCAPropertyName.CaType);
        }
        /// <inheritdoc />
        public Int32 GetCaCertificateCount() {
            return getIntegerProperty(AdcsCAPropertyName.CaSigCertCount);
        }
        /// <inheritdoc />
        public Byte[] GetCaCertificate(Int32 index) {
            return getBinaryProperty(AdcsCAPropertyName.CaSigCert, index);
        }
        /// <inheritdoc />
        public Byte[] GetLatestCaCertificate() {
            return getBinaryProperty(AdcsCAPropertyName.CaSigCert, MAX_INDEX);
        }
        /// <inheritdoc />
        public Byte[] GetCaCertificateChain(Int32 index) {
            return getBinaryProperty(AdcsCAPropertyName.CaSigCertChain, index);
        }
        /// <inheritdoc />
        public Byte[] GetLatestCaCertificateChain() {
            return getBinaryProperty(AdcsCAPropertyName.CaSigCertChain, MAX_INDEX);
        }
        /// <inheritdoc />
        public Int32 GetExchangeCertificateCount() {
            return getIntegerProperty(AdcsCAPropertyName.CaXchgCertCount);
        }
        /// <inheritdoc />
        public Byte[] GetExchangeCertificate() {
            return getBinaryProperty(AdcsCAPropertyName.CaXchgCert);
        }
        /// <inheritdoc />
        public Byte[] GetExchangeCertificateChain() {
            return getBinaryProperty(AdcsCAPropertyName.CaXchgCertChain);
        }
        /// <inheritdoc />
        public Byte[] GetBaseCrl(Int32 index) {
            return getBinaryProperty(AdcsCAPropertyName.BaseCrl, index);
        }
        /// <inheritdoc />
        public Byte[] GetLatestCertBaseCrl() {
            return getBinaryProperty(AdcsCAPropertyName.BaseCrl, MAX_INDEX);
        }
        /// <inheritdoc />
        public Byte[] GetDeltaCrl(Int32 index) {
            return getBinaryProperty(AdcsCAPropertyName.DeltaCrl, index);
        }
        /// <inheritdoc />
        public Byte[] GetLatestCertDeltaCrl() {
            return getBinaryProperty(AdcsCAPropertyName.DeltaCrl, MAX_INDEX);
        }
        /// <inheritdoc />
        public AdcsPropCertState GetCaCertState(Int32 index) {
            return (AdcsPropCertState)getIntegerProperty(AdcsCAPropertyName.CaCertState, index);
        }
        /// <inheritdoc />
        public AdcsPropCrlState GetCrlState(Int32 index) {
            return (AdcsPropCrlState)getIntegerProperty(AdcsCAPropertyName.CrlState, index);
        }
        /// <inheritdoc />
        public String GetDnsName() {
            return getStringProperty(AdcsCAPropertyName.DnsName);
        }
        /// <inheritdoc />
        public Boolean IsRoleSeparationEnabled() {
            return getIntegerProperty(AdcsCAPropertyName.RoleSeparationEnabled) > 0;
        }
        /// <inheritdoc />
        public Int32 GetKraCertUsedCount() {
            return getIntegerProperty(AdcsCAPropertyName.KraCertUsedCount);
        }
        /// <inheritdoc />
        public Int32 GetKraCertCount() {
            return getIntegerProperty(AdcsCAPropertyName.KraCertCount);
        }
        /// <inheritdoc />
        public Byte[] GetKraCertificate(Int32 index) {
            return getBinaryProperty(AdcsCAPropertyName.KraCert, index);
        }
        /// <inheritdoc />
        public AdcsPropKraCertStatus GetKraCertState(Int32 index) {
            return (AdcsPropKraCertStatus)getIntegerProperty(AdcsCAPropertyName.KraCertState, index);
        }
        /// <inheritdoc />
        public Boolean IsAdvancedServer() {
            return getIntegerProperty(AdcsCAPropertyName.AdvancedServer) > 0;
        }
        /// <inheritdoc />
        public String[,] GetCaTemplates() {
            String templates = getStringProperty(AdcsCAPropertyName.Templates);
            if (String.IsNullOrWhiteSpace(templates)) {
                return new String[0, 0];
            }

            String[] tempArray = templates.TrimEnd().Split('\n');
            String[,] retValue = new String[tempArray.Length / 2, 2];
            for (Int32 index = 0; index < tempArray.Length; index += 2) {
                retValue[index / 2, 0] = tempArray[index].TrimEnd();
                retValue[index / 2, 1] = tempArray[index + 1].TrimEnd();
            }

            return retValue;
        }
        /// <inheritdoc />
        public AdcsPropCrlPublishState GetBaseCrlPublishStatus(Int32 index) {
            return (AdcsPropCrlPublishState)getIntegerProperty(AdcsCAPropertyName.BaseCrlPublishStatus, index);
        }
        /// <inheritdoc />
        public AdcsPropCrlPublishState GetLatestCertBaseCrlPublishStatus() {
            return (AdcsPropCrlPublishState)getIntegerProperty(AdcsCAPropertyName.BaseCrlPublishStatus, MAX_INDEX);
        }
        /// <inheritdoc />
        public AdcsPropCrlPublishState GetDeltaCrlPublishStatus(Int32 index) {
            return (AdcsPropCrlPublishState)getIntegerProperty(AdcsCAPropertyName.DeltaCrlPublishStatus, index);
        }
        /// <inheritdoc />
        public AdcsPropCrlPublishState GetLatestCertDeltaCrlPublishStatus() {
            return (AdcsPropCrlPublishState)getIntegerProperty(AdcsCAPropertyName.DeltaCrlPublishStatus, MAX_INDEX);
        }
        /// <inheritdoc />
        public Byte[] GetCaCertChainAndCrl(Int32 index) {
            return getBinaryProperty(AdcsCAPropertyName.CaSigCertCrlChain, index);
        }
        /// <inheritdoc />
        public Byte[] GetLatestCaCertChainAndCrl() {
            return getBinaryProperty(AdcsCAPropertyName.CaSigCertCrlChain, MAX_INDEX);
        }
        /// <inheritdoc />
        public Byte[] GetLatestExchangeCertChainAndCrl() {
            return getBinaryProperty(AdcsCAPropertyName.CaXchgCertCrlChain);
        }
        /// <inheritdoc />
        public Int32 GetCaCertStatusCode(Int32 index) {
            return getIntegerProperty(AdcsCAPropertyName.CaCertStatusCode, index);
        }
        /// <inheritdoc />
        public Int32 GetLatestCaCertStatusCode() {
            return getIntegerProperty(AdcsCAPropertyName.CaCertStatusCode, MAX_INDEX);
        }
        /// <inheritdoc />
        public Byte[] GetForwardCrossCert(Int32 index) {
            return getBinaryProperty(AdcsCAPropertyName.CaForwardCrossCert, index);
        }
        /// <inheritdoc />
        public Byte[] GetBackwardCrossCert(Int32 index) {
            return getBinaryProperty(AdcsCAPropertyName.CaBackwardCrossCert, index);
        }
        /// <inheritdoc />
        public AdcsPropCertState GetForwardCrossCertState(Int32 index) {
            return (AdcsPropCertState)getIntegerProperty(AdcsCAPropertyName.CaForwardCrossCertState, index);
        }
        /// <inheritdoc />
        public AdcsPropCertState GetBackwardCrossCertState(Int32 index) {
            return (AdcsPropCertState)getIntegerProperty(AdcsCAPropertyName.CaBackwardCrossCertState, index);
        }
        /// <inheritdoc />
        public Int32 GetCaVersion(Int32 index) {
            return getIntegerProperty(AdcsCAPropertyName.CaCertVersion, index);
        }
        /// <inheritdoc />
        public String GetSanitizedShortCommonName() {
            return getStringProperty(AdcsCAPropertyName.SanitizedCaShortName);
        }
        /// <inheritdoc />
        public String[] GetCdpURLs(Int32 index) {
            return getStringProperty(AdcsCAPropertyName.CertCdpUrls, index)?.Trim().Split('\n');
        }
        /// <inheritdoc />
        public String[] GetLatestCertCdpURLs() {
            return getStringProperty(AdcsCAPropertyName.CertCdpUrls, MAX_INDEX)?.Trim().Split('\n');
        }
        /// <inheritdoc />
        public String[] GetAiaURLs(Int32 index) {
            return getStringProperty(AdcsCAPropertyName.CertAiaUrls, index)?.Trim().Split('\n');
        }
        /// <inheritdoc />
        public String[] GetLatestCertAiaURLs() {
            return getStringProperty(AdcsCAPropertyName.CertAiaUrls, MAX_INDEX)?.Trim().Split('\n');
        }
        /// <inheritdoc />
        public String[] GetOcspURLs(Int32 index) {
            return getStringProperty(AdcsCAPropertyName.CertAiaOcspUrls, index)?.Trim().Split('\n');
        }
        /// <inheritdoc />
        public String[] GetLatestCertOcspURLs() {
            return getStringProperty(AdcsCAPropertyName.CertAiaOcspUrls, MAX_INDEX)?.Trim().Split('\n');
        }
        /// <inheritdoc />
        public String GetLocaleName() {
            return getStringProperty(AdcsCAPropertyName.LocaleName);
        }
        /// <inheritdoc />
        public OidCollection GetSubjectTemplateOIDs() {
            var retValue = new OidCollection();
            getStringProperty(AdcsCAPropertyName.SubjectTemplateOIDs)
                ?.TrimEnd()
                .Split('\n')
                .ToList().ForEach(x => retValue.Add(new Oid(x)));
            return retValue;
        }
        #endregion
    }
}