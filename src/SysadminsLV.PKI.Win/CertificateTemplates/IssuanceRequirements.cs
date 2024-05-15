using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Management.ActiveDirectory;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateTemplates;

/// <summary>
/// Represents registration authority requirements. These are number of authorized signatures and authorized certificate application and/or issuance
/// policy requirements.
/// </summary>
public class IssuanceRequirements {
    readonly List<Oid> _certPolicies = [];
    readonly DsPropertyCollection _entry;
    CertificateTemplateEnrollmentFlags enrollmentFlags;

    internal IssuanceRequirements(IAdcsCertificateTemplate template) {
        initializeCom(template);
    }
    internal IssuanceRequirements(DsPropertyCollection Entry) {
        _entry = Entry;
        initializeDs();
    }

    /// <summary>
    /// Gets or sets whether the requests based on a referenced template are put to a pending state.
    /// </summary>
    public Boolean CAManagerApproval { get; private set; }
    /// <summary>
    /// Gets the number of registration agent (aka enrollment agent) signatures that are required on a request
    /// that references this template.
    /// </summary>
    public Int32 SignatureCount { get; private set; }
    /// <summary>
    /// Gets a set of application policy OID for the enrollment agent certificates.
    /// </summary>
    public Oid ApplicationPolicy { get; private set; }
    /// <summary>
    /// Gets a set of certificate policy OIDs for the enrollment agent certificates.
    /// </summary>
    public OidCollection CertificatePolicies {
        get {
            var oids = new OidCollection();
            _certPolicies.ForEach(x => oids.Add(x));
            return oids;
        }
    }
    /// <summary>
    /// Gets the certificate re-enrollment requirements. If the property is set to <strong>True</strong>,
    /// existing valid certificate is sufficient for re-enrollment, otherwise, the same enrollment
    /// criteria is required for certificate renewal as was used for initial enrollment.
    /// </summary>
    public Boolean ExistingCertForRenewal => (enrollmentFlags & CertificateTemplateEnrollmentFlags.ReenrollExistingCert) != 0;

    void initializeDs() {
        enrollmentFlags = (CertificateTemplateEnrollmentFlags)_entry[DsUtils.PropPkiEnrollFlags];
        SignatureCount = (Int32)_entry[DsUtils.PropPkiRaSignature];
        if (SignatureCount > 0) {
            readRaPolicies();
            String ap = (String)_entry[DsUtils.PropPkiRaAppPolicy];
            if (ap == null) {
                return;
            }
            if (ap.Contains("`")) {
                String[] delimiter = ["`"];
                String[] strings = ap.Split(delimiter, StringSplitOptions.RemoveEmptyEntries);
                for (Int32 index = 0; index < strings.Length; index += 3) {
                    switch (strings[index]) {
                        case DsUtils.PropPkiRaAppPolicy: ApplicationPolicy = new Oid(strings[index + 2]); break;
                    }
                }
            } else {
                ApplicationPolicy = new Oid(ap);
            }
        }
        if ((enrollmentFlags & CertificateTemplateEnrollmentFlags.CAManagerApproval) > 0) {
            CAManagerApproval = true;
        }
    }
    void readRaPolicies() {
        try {
            Object[] RaObject = (Object[])_entry[DsUtils.PropPkiRaCertPolicy];
            if (RaObject != null) {
                foreach (Object obj in RaObject) {
                    _certPolicies.Add(new Oid(obj.ToString()));
                }
            }
        } catch {
            String RaString = (String)_entry[DsUtils.PropPkiRaCertPolicy];
            _certPolicies.Add(new Oid(RaString));
        }
    }
    void initializeCom(IAdcsCertificateTemplate template) {
        SignatureCount = template.RASignatureCount;
        enrollmentFlags = template.EnrollmentFlags;
        if (SignatureCount > 0) {
            if (template.RAApplicationPolicies.Length > 0) {
                ApplicationPolicy = new Oid(template.RAApplicationPolicies[0]);
            }

            foreach (String raCertPolicy in template.RACertificatePolicies) {
                _certPolicies.Add(new Oid(raCertPolicy));
            }
        }
        if ((template.EnrollmentFlags & CertificateTemplateEnrollmentFlags.CAManagerApproval) > 0) {
            CAManagerApproval = true;
        }
    }

    /// <summary>
    /// Returns a textual representation of the certificate template issuance settings.
    /// </summary>
    /// <returns>A textual representation of the certificate template issuance settings.</returns>
    public override String ToString() {
        var SB = new StringBuilder();
        SB.Append("[Issuance Requirements]" + Environment.NewLine);
        SB.Append("  Authorized signature count: " + SignatureCount + Environment.NewLine);
        if (SignatureCount > 0) {
            if (ApplicationPolicy == null) {
                SB.Append("  Application policy required: None" + Environment.NewLine);
            } else {
                SB.Append("  Application policy required: " + ApplicationPolicy.Format(true) + Environment.NewLine);
            }
            if (!_certPolicies.Any()) {
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