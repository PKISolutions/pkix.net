using System;
using System.Runtime.InteropServices;
using Interop.CERTENROLLLib;
using PKI.CertificateTemplates;
using SysadminsLV.PKI.Dcom.Implementations;
using SysadminsLV.PKI.Management.ActiveDirectory;
using SysadminsLV.PKI.Management.CertificateServices;

namespace SysadminsLV.PKI.CertificateTemplates;

/// <summary>
/// Represents unified factory for <see cref="CertificateTemplate"/> class.
/// </summary>
public static class CertificateTemplateFactory {
    /// <summary>
    /// Creates an instance of <see cref="CertificateTemplate"/> from <see cref="IAdcsCertificateTemplate"/> interface implementation.
    /// </summary>
    /// <param name="templateInfo">Template information.</param>
    /// <returns>Certificate template.</returns>
    public static CertificateTemplate CreateFromTemplateInfo(IAdcsCertificateTemplate templateInfo) {
        return new CertificateTemplate(templateInfo);
    }
    /// <summary>
    /// Creates an instance of <see cref="CertificateTemplate"/> from template common name using local registry cache.
    /// </summary>
    /// <param name="commonName">Template common name.</param>
    /// <returns>Certificate template.</returns>
    /// <exception cref="ArgumentException">Requested template was not found.</exception>
    public static CertificateTemplate CreateFromCommonNameRegistry(String commonName) {
        return new CertificateTemplate(new RegCertificateTemplate(commonName));
    }
    /// <summary>
    /// Creates an instance of <see cref="CertificateTemplate"/> from template common name using Active Directory storage.
    /// </summary>
    /// <param name="commonName">Template common name.</param>
    /// <returns>Certificate template.</returns>
    /// <exception cref="ArgumentException">Requested template was not found.</exception>
    public static CertificateTemplate CreateFromCommonNameDs(String commonName) {
        return new CertificateTemplate(DsCertificateTemplate.FromCommonName(commonName));
    }
    /// <summary>
    /// Creates an instance of <see cref="CertificateTemplate"/> from template display name using Active Directory storage.
    /// </summary>
    /// <param name="displayName">Template display name.</param>
    /// <returns>Certificate template.</returns>
    /// <exception cref="ArgumentException">Requested template was not found.</exception>
    public static CertificateTemplate CreateFromDisplayNameDs(String displayName) {
        return new CertificateTemplate(DsCertificateTemplate.FromDisplayName(displayName));
    }
    /// <summary>
    /// Creates an instance of <see cref="CertificateTemplate"/> from template OID value using Active Directory storage.
    /// </summary>
    /// <param name="oid">Template OID string in dot-decimal notation.</param>
    /// <returns>Certificate template.</returns>
    /// <exception cref="ArgumentException">Requested template was not found.</exception>
    public static CertificateTemplate CreateFromOidDs(String oid) {
        return new CertificateTemplate(DsCertificateTemplate.FromOid(oid));
    }
    /// <summary>
    /// Creates an instance of <see cref="CertificateTemplate"/> from <see cref="IX509CertificateTemplate"/> COM interface.
    /// </summary>
    /// <param name="template">COM template object.</param>
    /// <returns>Certificate template.</returns>
    /// <exception cref="COMException">Any exception propagated from COM object.</exception>
    public static CertificateTemplate CreateFromCertEnrollTemplate(IX509CertificateTemplate template) {
        return new CertificateTemplate(new CertEnrollCertificateTemplate(template));
    }
}
