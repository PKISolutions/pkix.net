﻿using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Interop.CERTENROLLLib;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PKI.CertificateTemplates;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Security.AccessControl;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Win.Tests.CertificateTemplates;
[TestClass]
public class CertificateTemplateTests {
    [TestMethod]
    public void TestRegTemplates() {
        foreach (CertificateTemplate template in CertificateTemplateFactory.GetTemplatesFromDs()) {
            Console.WriteLine(template.Name);
            CertificateTemplate refTemplate = CertificateTemplateFactory.CreateFromCommonNameRegistry(template.Name);
            assertTemplate(template, refTemplate);
        }
    }
    [TestMethod]
    public void TestDsTemplates() {
        foreach (CertificateTemplate template in CertificateTemplateFactory.GetTemplatesFromDs()) {
            Console.WriteLine(template.Name);
            CertificateTemplate refTemplate = CertificateTemplateFactory.CreateFromCommonNameDs(template.Name);
            assertTemplate(template, refTemplate);
        }
    }
    [TestMethod]
    public void TestCertEnrollTemplates() {
        CertificateTemplateCollection col = CertificateTemplateFactory.GetTemplatesFromDs();
        String serializedString = col.Export(CertificateTemplateExportFormat.XCep);
        var policy = new CX509EnrollmentPolicyWebServiceClass();
        policy.InitializeImport(Encoding.UTF8.GetBytes(serializedString));
        IX509CertificateTemplates templates = policy.GetTemplates();
        Assert.AreEqual(col.Count, templates.Count);
        for (Int32 index = 0; index < col.Count; index++) {
            CertificateTemplate source = col[index];
            Console.WriteLine(source.Name);
            CertificateTemplate refTemplate = CertificateTemplateFactory.CreateFromCertEnrollTemplate(templates[index]);
            assertTemplate(source, refTemplate);
        }

        CryptographyUtils.ReleaseCom(policy);
        CryptographyUtils.ReleaseCom(templates);
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
        Assert.AreEqual(sSettings.SupersededTemplates.Length, tSettings.SupersededTemplates.Length);
        if (sSettings.SupersededTemplates.Length > 0) {
            Assert.IsTrue(sSettings.SupersededTemplates.OrderBy(x => x).SequenceEqual(tSettings.SupersededTemplates.OrderBy(x => x)));
        }
        Assert.AreEqual(sSettings.EnrollmentOptions, tSettings.EnrollmentOptions);
        Assert.AreEqual(sSettings.GeneralFlags, tSettings.GeneralFlags);
        
        // Cryptography
        CryptographyTemplateSettings sCrypto = sSettings.Cryptography;
        CryptographyTemplateSettings tCrypto = tSettings.Cryptography;
        Assert.AreEqual(sCrypto.ProviderList.Length, tCrypto.ProviderList.Length);
        if (sCrypto.ProviderList.Length > 0) {
            Assert.IsTrue(sCrypto.ProviderList.OrderBy(x => x).SequenceEqual(tCrypto.ProviderList.OrderBy(x => x)));
        }
        assertOid(sCrypto.KeyAlgorithm, tCrypto.KeyAlgorithm);
        assertOid(sCrypto.HashAlgorithm, tCrypto.HashAlgorithm);
        Assert.AreEqual(sCrypto.MinimalKeyLength, tCrypto.MinimalKeyLength);
        Assert.AreEqual(sCrypto.PrivateKeyOptions, tCrypto.PrivateKeyOptions);
        Assert.AreEqual(sCrypto.KeyUsage, tCrypto.KeyUsage);
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
        assertExtensions(sSettings.Extensions, tSettings.Extensions);
    }
    static void assertOid(Oid source, Oid target) {
        Assert.IsNotNull(source);
        Assert.IsNotNull(target);
        //Assert.AreEqual(source.FriendlyName, target.FriendlyName);
        Assert.AreEqual(source.Value, target.Value);
    }
    static void assertExtensions(X509ExtensionCollection source, X509ExtensionCollection target) {
        Assert.AreEqual(source.Count, target.Count);
        for (Int32 index = 0; index < source.Count; index++) {
            assertOid(source[index].Oid, target[index].Oid);
            Assert.AreEqual(source[index].Critical, target[index].Critical);
            Assert.IsTrue(source[index].RawData.SequenceEqual(target[index].RawData));
        }
    }

    [TestMethod]
    public void TestRegExportImport() {
        var col = new CertificateTemplateCollection();
        foreach (CertificateTemplate template in CertificateTemplateFactory.GetTemplatesFromDs()) {
            Console.WriteLine(template.Name);
            CertificateTemplate refTemplate = CertificateTemplateFactory.CreateFromCommonNameRegistry(template.Name);
            col.Add(refTemplate);
        }
        String serializedString = col.Export(CertificateTemplateExportFormat.XCep);
        var col2 = new CertificateTemplateCollection();
        col2.Import(serializedString, CertificateTemplateExportFormat.XCep);

        Assert.AreEqual(col.Count, col2.Count);
        for (Int32 index = 0; index < col.Count; index++) {
            CertificateTemplate source = col[index];
            Console.WriteLine(source.Name);
            CertificateTemplate target = col2[index];
            assertTemplate(source, target);
        }
    }
    [TestMethod]
    public void TestDsExportImport() {
        var col = new CertificateTemplateCollection();
        foreach (CertificateTemplate template in CertificateTemplateFactory.GetTemplatesFromDs()) {
            Console.WriteLine(template.Name);
            CertificateTemplate refTemplate = CertificateTemplateFactory.CreateFromCommonNameDs(template.Name);
            col.Add(refTemplate);
        }
        String serializedString = col.Export(CertificateTemplateExportFormat.XCep);
        var col2 = new CertificateTemplateCollection();
        col2.Import(serializedString, CertificateTemplateExportFormat.XCep);

        Assert.AreEqual(col.Count, col2.Count);
        for (Int32 index = 0; index < col.Count; index++) {
            CertificateTemplate source = col[index];
            Console.WriteLine(source.Name);
            CertificateTemplate target = col2[index];
            assertTemplate(source, target);
        }
    }

    [TestMethod]
    public void TestDsTemplateAcl() {
        foreach (CertificateTemplate template in CertificateTemplateFactory.GetTemplatesFromDs()) {
            Console.WriteLine(template.Name);
            CertTemplateSecurityDescriptor acl = template.GetSecurityDescriptor();
            Assert.IsNotNull(acl);
        }
    }
    [TestMethod]
    public void TestRegTemplateAcl() {
        foreach (CertificateTemplate template in CertificateTemplateFactory.GetTemplatesFromRegistry()) {
            Console.WriteLine(template.Name);
            CertTemplateSecurityDescriptor acl = template.GetSecurityDescriptor();
            Assert.IsNotNull(acl);
        }
    }
    [TestMethod]
    public void TestCertEnrollTemplateAcl() {
        String serializedString = CertificateTemplateFactory.GetTemplatesFromDs().Export(CertificateTemplateExportFormat.XCep);
        var col = new CertificateTemplateCollection();
        col.Import(serializedString, CertificateTemplateExportFormat.XCep);
        foreach (CertificateTemplate template in col) {
            Console.WriteLine(template.Name);
            CertTemplateSecurityDescriptor acl = template.GetSecurityDescriptor();
            Assert.IsNotNull(acl);
        }
    }
}
