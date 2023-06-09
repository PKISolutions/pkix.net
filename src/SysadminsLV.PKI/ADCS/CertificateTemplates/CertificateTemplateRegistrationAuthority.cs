using System;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.PKI.Cryptography;

namespace SysadminsLV.PKI.ADCS.CertificateTemplates;

/// <summary>
/// Represents registration authority requirements. These are number of authorized signatures and authorized certificate application and/or issuance
/// policy requirements.
/// </summary>
public class CertificateTemplateRegistrationAuthority {
    readonly OidCollection _appPolicies = new();
    readonly OidCollection _certPolicies = new();

    internal CertificateTemplateRegistrationAuthority(IAdcsCertificateTemplate template) {
        CAManagerApproval = (template.EnrollmentFlags & CertificateTemplateEnrollmentFlags.CAManagerApproval) > 0;
        SignatureCount = template.RASignatureCount;
        foreach (String oid in template.RAApplicationPolicies) {
            _appPolicies.Add(new Oid(oid));
        }
        foreach (String oid in template.RACertificatePolicies) {
            _certPolicies.Add(new Oid(oid));
        }
        ExistingCertForRenewal = (template.EnrollmentFlags & CertificateTemplateEnrollmentFlags.ReenrollExistingCert) > 0;
    }
    
    /// <summary>
    /// Gets or sets whether the requests based on a referenced template are put to a pending state.
    /// </summary>
    public Boolean CAManagerApproval { get; }
    /// <summary>
    /// Gets the number of registration agent (aka enrollment agent) signatures that are required on a request
    /// that references this template.
    /// </summary>
    public Int32 SignatureCount { get; }
    /// <summary>
    /// Gets a set of application policy OID for the enrollment agent certificates.
    /// </summary>
    public OidCollection ApplicationPolicies => _appPolicies.Duplicate();
    /// <summary>
    /// Gets a set of certificate policy OIDs for the enrollment agent certificates.
    /// </summary>
    public OidCollection CertificatePolicies => _certPolicies.Duplicate();
    /// <summary>
    /// Gets the certificate re-enrollment requirements. If the property is set to <strong>True</strong>,
    /// existing valid certificate is sufficient for re-enrollment, otherwise, the same enrollment
    /// criteria is required for certificate renewal as was used for initial enrollment.
    /// </summary>
    public Boolean ExistingCertForRenewal { get; }

    /// <summary>
    /// Returns a textual representation of the certificate template issuance settings.
    /// </summary>
    /// <returns>A textual representation of the certificate template issuance settings.</returns>
    public override String ToString() {
        var SB = new StringBuilder();
        SB.Append("[Issuance Requirements]" + Environment.NewLine);
        SB.Append("  Authorized signature count: " + SignatureCount + Environment.NewLine);
        if (SignatureCount > 0) {
            if (_appPolicies.Count == 0) {
                SB.Append("  Application policies required: None" + Environment.NewLine);
            } else {
                foreach (Oid oid in CertificatePolicies) {
                    SB.Append(oid.Format(true) + "; ");
                }
            }
            if (_certPolicies.Count == 0) {
                SB.Append("  Issuance policies required: None" + Environment.NewLine);
            } else {
                SB.Append("  Issuance policies required: ");
                foreach (Oid oid in CertificatePolicies) {
                    SB.Append(oid.Format(true) + "; ");
                }
                SB.Append(Environment.NewLine);
            }
        }
        SB.Append(ExistingCertForRenewal
            ? "  Reenrollment requires: existing valid certificate."
            : "  Reenrollment requires: same criteria as for enrollment.");
        return SB.ToString();
    }
}