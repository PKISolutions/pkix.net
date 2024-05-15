#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Interop.CERTENROLLLib;
using PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.CertificateTemplates;

/// <summary>
/// Represents <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/08ec4475-32c2-457d-8c27-5a176660a210">[MS-XCEP]</see>
/// compatible certificate template formatter (serializer).
/// </summary>
class CertificateTemplateXCepFormatter : ICertificateTemplateFormatter {
    readonly List<Oid2> _oidList = [];

    #region Serialize

    /// <summary>
    /// Exports current collection into a <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/08ec4475-32c2-457d-8c27-5a176660a210">[MS-XCEP]</see>
    /// protocol compatible format.
    /// </summary>
    /// <returns>[MS=XCEP] compatible certificate template XML dump.</returns>
    public String Serialize(ICollection<CertificateTemplate> templates) {
        var sb = new StringBuilder();
        sb.Append($"""
                   <GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
                       <response>
                           {getNullableSection("policyID", "{" + Guid.Empty + "}")}
                           {getNullableSection("policyFriendlyName")}
                           {getNullableSection("nextUpdateHours")}
                           {getNullableSection("policiesNotChanged")}
                   """);
        _oidList.Clear();
        if (templates.Count == 0) {
            sb.Append(getNullableSection("policies"));
        } else {
            sb.Append("<policies>");
            foreach (CertificateTemplate template in templates) {
                exportSingleTemplate(sb, template);
            }
            sb.Append("</policies>");
        }
        sb.Append("</response>");
        //sb.Append(getNullableSection("cAs"));
        sb.Append(getOidTable());
        sb.Append("</GetPoliciesResponse>");

        return sb.ToString();
    }

    void exportSingleTemplate(StringBuilder sb, CertificateTemplate template) {
        sb.Append("<policy>");
        sb.Append(getTemplateIdSection(template));
        sb.Append(getNullableSection("cAs"));
        sb.Append("<attributes>");
        sb.Append(getNullableSection("commonName", template.Name));
        sb.Append(getNullableSection("policySchema", template.SchemaVersion));
        sb.Append(getValidityPeriodSection(template));
        sb.Append(getPermissionSection());
        sb.Append(getPrivateKeyAttributesSection(template.Settings.Cryptography));
        sb.Append(getRevisionSection(template));
        sb.Append(getSupersededTemplatesSection(template));
        sb.Append(getNullableSection("privateKeyFlags", (Int32)template.Settings.Cryptography.PrivateKeyOptions));
        sb.Append(getNullableSection("subjectNameFlags", (Int32)template.Settings.SubjectName));
        sb.Append(getNullableSection("enrollmentFlags", (Int32)(template.Settings.EnrollmentOptions & ~CertificateTemplateEnrollmentFlags.Autoenrollment)));
        sb.Append(getNullableSection("generalFlags", (Int32)template.Settings.GeneralFlags));
        sb.Append(getRequestHashSection(template.Settings.Cryptography));
        sb.Append(getRegistrationAuthoritySection(template.Settings.RegistrationAuthority));
        sb.Append(getKeyArchivalSection(template.Settings.KeyArchivalSettings));
        sb.Append(getExtensionsSection(template.Settings.Extensions));
        sb.Append("</attributes></policy>");
    }

    String getTemplateIdSection(CertificateTemplate template) {
        Int32 oidID = getOidIndex(new Oid2(template.OID, OidGroup.Template, false));

        return getNullableSection("policyOIDReference", oidID);
    }
    static String getValidityPeriodSection(CertificateTemplate template) {
        Int64 period = getSecondsFromPeriod(template.Settings.ValidityPeriod);
        String content = getNullableSection("validityPeriodSeconds", period);
        period = getSecondsFromPeriod(template.Settings.RenewalPeriod);
        content += getNullableSection("renewalPeriodSeconds", period);

        return getNullableSection("certificateValidity", content);
    }
    static String getPermissionSection() {
        String content = getNullableSection("enroll", false) + getNullableSection("autoEnroll", false);

        return getNullableSection("permission", content);
    }
    static String getRevisionSection(CertificateTemplate template) {
        String content = getNullableSection("majorRevision", template.GetMajorVersion())
                         + getNullableSection("minorRevision", template.GetMinorVersion());

        return getNullableSection("revision", content);
    }
    String getPrivateKeyAttributesSection(CryptographyTemplateSettings templateCrypto) {
        CngKeyUsages cngKeyUsage = templateCrypto.CNGKeyUsage;
        String keyUsageString = cngKeyUsage == CngKeyUsages.None
            ? getNullableSection("keyUsageProperty")
            : getNullableSection("keyUsageProperty", (Int32)cngKeyUsage);
        String privateKeyPermissionsString = getNullableSection("permissions", templateCrypto.PrivateKeySecuritySDDL);
        String pubKeyAlgString;
        if (templateCrypto.KeyAlgorithm.Value == AlgorithmOid.RSA) {
            pubKeyAlgString = getNullableSection("algorithmOIDReference");
        } else {
            Int32 oidID = getOidIndex(new Oid2(templateCrypto.KeyAlgorithm, OidGroup.PublicKeyAlgorithm, false));
            pubKeyAlgString = getNullableSection("algorithmOIDReference", oidID);
        }


        String cspString = templateCrypto.ProviderList.Length == 0
            ? getNullableSection("cryptoProviders")
            : getNullableSection("cryptoProviders",
                templateCrypto.ProviderList.Aggregate(String.Empty, (current, provName) =>
                                                                        current + getNullableSection("provider", provName)));

        String content = $"""
                          {getNullableSection("minimalKeyLength", templateCrypto.MinimalKeyLength)}
                          {getNullableSection("keySpec", (Int32)templateCrypto.KeySpec)}
                          {keyUsageString}
                          {privateKeyPermissionsString}
                          {pubKeyAlgString}
                          {cspString}
                          """;
        return getNullableSection("privateKeyAttributes", content);
    }
    static String getSupersededTemplatesSection(CertificateTemplate template) {
        if (template.Settings.SupersededTemplates.Length == 0) {
            return getNullableSection("supersededPolicies");
        }

        String supersedeTemplatesString = template.Settings.SupersededTemplates.
            Aggregate(String.Empty, (current, supersededTemplateName) => current + getNullableSection("commonName", supersededTemplateName));

        return getNullableSection("supersededPolicies", supersedeTemplatesString);
    }
    String getKeyArchivalSection(KeyArchivalOptions keyArchival) {
        if (!keyArchival.KeyArchival) {
            return getNullableSection("keyArchivalAttributes");
        }

        Int32 oidID = getOidIndex(new Oid2(keyArchival.EncryptionAlgorithm, OidGroup.EncryptionAlgorithm, false));
        String content = getNullableSection("symmetricAlgorithmOIDReference", oidID)
                         + getNullableSection("symmetricAlgorithmKeyLength", keyArchival.KeyLength);

        return getNullableSection("keyArchivalAttributes", content);
    }
    String getRequestHashSection(CryptographyTemplateSettings templateCrypto) {
        if (templateCrypto.HashAlgorithm.Value == AlgorithmOid.SHA1) {
            return getNullableSection("hashAlgorithmOIDReference");
        }

        Int32 oidID = getOidIndex(new Oid2(templateCrypto.HashAlgorithm, OidGroup.HashAlgorithm, false));
        return getNullableSection("hashAlgorithmOIDReference", oidID);
    }
    String getRegistrationAuthoritySection(IssuanceRequirements regAuthority) {
        if (regAuthority.SignatureCount == 0) {
            return getNullableSection("rARequirements");
        }

        var sb = new StringBuilder(getNullableSection("rASignatures"), regAuthority.SignatureCount);
        // EA application policy. Can be only one.
        if (regAuthority.ApplicationPolicy == null) {
            sb.Append(getNullableSection("rAEKUs"));
        } else {
            Int32 oidID = getOidIndex(new Oid2(regAuthority.ApplicationPolicy, OidGroup.EnhancedKeyUsage, false));
            sb.Append(getNullableSection("rAEKUs", getNullableSection("oIDReference", oidID)));
        }

        // EA certificate policies. Can be multiple
        if (regAuthority.CertificatePolicies.Count > 0) {
            sb.Append(getNullableSection("rAPolicies"));
        } else {
            String oidListString = String.Empty;
            foreach (Oid oid in regAuthority.CertificatePolicies) {
                Int32 oidID = getOidIndex(new Oid2(oid, OidGroup.Policy, false));
                oidListString += getNullableSection("oIDReference", oidID);
            }
            sb.Append(getNullableSection("rAPolicies", oidListString));
        }

        return getNullableSection("rARequirements", sb.ToString());
    }
    String getExtensionsSection(X509ExtensionCollection extensions) {
        String content = String.Empty;
        foreach (X509Extension extension in extensions) {
            content += getExtensionSection(extension);
        }

        return getNullableSection("extensions", content);
    }

    #region Helper functions

    static String getNullableSection(String sectionName, Object? value = null) {
        if (value is Boolean) {
            value = value.ToString().ToLower();
        }
        return value == null
            ? $"<{sectionName} xmlns:a=\"http://www.w3.org/2001/XMLSchema-instance\" a:nil=\"true\"/>"
            : $"<{sectionName}>{value}</{sectionName}>";
    }

    Int32 getOidIndex(Oid2 oid) {
        Int32 index = _oidList.IndexOf(oid);
        if (index >= 0) {
            return index;
        }
        _oidList.Add(oid);

        return _oidList.Count - 1;
    }

    static Int64 getSecondsFromPeriod(String periodString) {
        MatchCollection matches = Regex.Matches(periodString, @"(\d+)\s(\w+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        Int32 period = Convert.ToInt32(matches[0].Groups[1].Value);
        String units = matches[0].Groups[2].Value;
        return units switch {
            "hours" => period * 3600,
            "days" => period * 3600 * 24,
            "weeks" => period * 3600 * 168,
            "months" => period * 3600 * 720,
            "years" => period * 3600 * 8760,
            _ => throw new ArgumentException(
                $"Specified period string '{periodString}' doesn't represent valid period string.")
        };
    }
    String getExtensionSection(X509Extension extension) {
        Int32 oidID = getOidIndex(new Oid2(extension.Oid, OidGroup.ExtensionOrAttribute, false));
        Boolean isCritical = extension.Critical;
        String value = Convert.ToBase64String(extension.RawData);

        return getNullableSection("extension",
            getNullableSection("oIDReference", oidID)
            + getNullableSection("critical", isCritical)
            + getNullableSection("value", value));
    }
    String getOidTable() {
        if (_oidList.Count == 0) {
            return getNullableSection("oIDs");
        }
        var sb = new StringBuilder();
        for (Int32 index = 0; index < _oidList.Count; index++) {
            Oid2 oid = _oidList[index];
            sb.Append(getNullableSection("oID",
                getNullableSection("value", oid.Value)
                + getNullableSection("group", (Int32)oid.OidGroup)
                + getNullableSection("oIDReferenceID", index)
                + $"<defaultName>{oid.FriendlyName}</defaultName>"));
        }

        return getNullableSection("oIDs", sb);
    }

    #endregion

    #endregion

    #region Deserialize

    /// <inheritdoc />
    public CertificateTemplateCollection Deserialize(String serializedString) {
        var policy = new CX509EnrollmentPolicyWebService();
        var retValue = new CertificateTemplateCollection();
        try {
            policy.InitializeImport(Encoding.UTF8.GetBytes(serializedString));
            foreach (IX509CertificateTemplate comTemplate in policy.GetTemplates()) {
                retValue.Add(new CertificateTemplate(comTemplate));
                CryptographyUtils.ReleaseCom(comTemplate);
            }
        } catch (Exception ex) {
            throw new Exception("Failed to deserialize certificate templates. See inner exception for more details.", ex);
        } finally {
            CryptographyUtils.ReleaseCom(policy);
        }
        
        return retValue;
    }

    #endregion
}
