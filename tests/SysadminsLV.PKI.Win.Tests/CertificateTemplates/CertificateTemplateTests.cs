using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Interop.CERTENROLLLib;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PKI.CertificateTemplates;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Dcom.Implementations;
using SysadminsLV.PKI.Management.ActiveDirectory;
using SysadminsLV.PKI.Management.CertificateServices;

namespace SysadminsLV.PKI.Win.Tests.CertificateTemplates;
[TestClass]
public class CertificateTemplateTests {
    [TestMethod]
    public void TestRegTemplates() {
        foreach (CertificateTemplate template in CertificateTemplate.EnumTemplates()) {
            var regTemplate = new RegCertificateTemplate(template.Name);
            var refTemplate = new CertificateTemplate(regTemplate);
            assertTemplate(template, refTemplate);
        }
    }
    public void TestDsTemplates() {
        foreach (CertificateTemplate template in CertificateTemplate.EnumTemplates()) {
            var dsTemplate = new DsCertificateTemplate(template.Name);
            var refTemplate = new CertificateTemplate(dsTemplate);
            assertTemplate(template, refTemplate);
        }
    }
    public void TestCertEnrollTemplates() {
        var col = new CertificateTemplateCollection(CertificateTemplate.EnumTemplates());
        String serializedString = col.Export(CertificateTemplateExportFormat.XCep);
        var policy = new CX509EnrollmentPolicyWebService();
        policy.InitializeImport(Encoding.UTF8.GetBytes(serializedString));
        IX509CertificateTemplates templates = policy.GetTemplates();
        Assert.AreEqual(col.Count, templates.Count);
        for (Int32 index = 0; index < col.Count; index++) {
            CertificateTemplate source = col[index];
            var certEnrollTemplate = new CertEnrollCertificateTemplate(templates[index]);
            var refTemplate = new CertificateTemplate(certEnrollTemplate);
            assertTemplate(source, refTemplate);
        }
    }
    static void assertTemplate(CertificateTemplate source, CertificateTemplate target) {
        Assert.AreEqual(source.Name, target.Name);
        Assert.AreEqual(source.DisplayName, target.DisplayName);
        assertOid(source.OID, target.OID);
        Assert.AreEqual(source.Version, target.Version);
        Assert.AreEqual(source.SchemaVersion, target.SchemaVersion);
        Assert.AreEqual(source.AutoenrollmentAllowed, target.AutoenrollmentAllowed);
        Assert.AreEqual(source.SupportedCA, target.SupportedCA);
        Assert.AreEqual(source.SupportedClient, target.SupportedClient);
        
        // settings
        CertificateTemplateSettings sSettings = source.Settings;
        CertificateTemplateSettings tSettings = target.Settings;
        Assert.AreEqual(sSettings.ValidityPeriod, tSettings.ValidityPeriod);
        Assert.AreEqual(sSettings.RenewalPeriod, tSettings.RenewalPeriod);
        Assert.AreEqual(sSettings.SubjectType, tSettings.SubjectType);
        Assert.AreEqual(sSettings.SubjectName, tSettings.SubjectName);
        Assert.AreEqual(sSettings.Purpose, tSettings.Purpose);
        Assert.IsTrue(sSettings.SupersededTemplates.SequenceEqual(tSettings.SupersededTemplates));
        Assert.AreEqual(sSettings.EnrollmentOptions, tSettings.EnrollmentOptions);
        Assert.AreEqual(sSettings.GeneralFlags, tSettings.GeneralFlags);
        
        // Cryptography
        CryptographyTemplateSettings sCrypto = sSettings.Cryptography;
        CryptographyTemplateSettings tCrypto = tSettings.Cryptography;
        Assert.IsTrue(sCrypto.ProviderList.SequenceEqual(tCrypto.ProviderList));
        assertOid(sCrypto.KeyAlgorithm, tCrypto.KeyAlgorithm);
        assertOid(sCrypto.HashAlgorithm, tCrypto.HashAlgorithm);
        Assert.AreEqual(sCrypto.MinimalKeyLength, tCrypto.MinimalKeyLength);
        Assert.AreEqual(sCrypto.PrivateKeyOptions, tCrypto.PrivateKeyOptions);
        Assert.AreEqual(sCrypto.KeySpec, tCrypto.KeySpec);
        Assert.AreEqual(sCrypto.PrivateKeySecuritySDDL, tCrypto.PrivateKeySecuritySDDL);

        // Registration Authority (issuance requirements)
        IssuanceRequirements sRA = sSettings.RegistrationAuthority;
        IssuanceRequirements tRA = tSettings.RegistrationAuthority;
        Assert.AreEqual(sRA.CAManagerApproval, tRA.CAManagerApproval);
        Assert.AreEqual(sRA.SignatureCount, tRA.SignatureCount);
        Assert.AreEqual(sRA.ExistingCertForRenewal, tRA.ExistingCertForRenewal);
        if (sRA.ApplicationPolicy != null) {
            assertOid(sRA.ApplicationPolicy, tRA.ApplicationPolicy);
        }
        Assert.AreEqual(sRA.CertificatePolicies.Count, tRA.CertificatePolicies.Count);
        for (Int32 index = 0; index < sRA.CertificatePolicies.Count; index++) {
            assertOid(sRA.CertificatePolicies[index], tRA.CertificatePolicies[index]);
        }

        // Key Archival settings
        KeyArchivalOptions sKRA = sSettings.KeyArchivalSettings;
        KeyArchivalOptions tKRA = tSettings.KeyArchivalSettings;
        Assert.AreEqual(sKRA.KeyArchival, tKRA.KeyArchival);
        Assert.AreEqual(sKRA.KeyLength, tKRA.KeyLength);
        if (sKRA.EncryptionAlgorithm != null) {
            assertOid(sKRA.EncryptionAlgorithm, tKRA.EncryptionAlgorithm);
        }

        // Extensions
    }
    static void assertOid(Oid source, Oid target) {
        Assert.IsNotNull(source);
        Assert.IsNotNull(target);
        Assert.AreEqual(source.FriendlyName, target.FriendlyName);
        Assert.AreEqual(source.Value, target.Value);
    }
    [TestMethod]
    public void Test2() {
        var col = new CertificateTemplateCollection();
        var t = CertificateTemplate.FromCommonName("rdp-tlsv3");
        col.Add(t);
        var s = col.Export(CertificateTemplateExportFormat.XCep);
        var col2 = new CertificateTemplateCollection();
        col2.Import(s, CertificateTemplateExportFormat.XCep);
    }
}
