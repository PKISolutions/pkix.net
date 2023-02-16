using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tests.Properties;

namespace SysadminsLV.PKI.Tests.Cryptography.X509Certificates;
[TestClass]
public class X509ExtensionsTests {
    [TestMethod]
    public void TestSANExtensionDecode() {
        var asn = new AsnEncodedData(Convert.FromBase64String(Extensions.SAN));
        var ext = new X509SubjectAlternativeNamesExtension(asn, false);
        Assert.IsFalse(ext.Critical, "Extension is critical.");
        Assert.IsTrue(ext.Oid.Value == "2.5.29.17");
        Assert.AreEqual(ext.AlternativeNames.Count, 9);

        Assert.AreEqual(ext.AlternativeNames[0].Type, X509AlternativeNamesEnum.DirectoryName);
        Assert.IsTrue(String.Equals(ext.AlternativeNames[0].Value, "CN=main, OU=test, DC=com"));

        Assert.AreEqual(ext.AlternativeNames[1].Type, X509AlternativeNamesEnum.DnsName);
        Assert.IsTrue(String.Equals(ext.AlternativeNames[1].Value, "www.contoso.com"));

        Assert.AreEqual(ext.AlternativeNames[2].Type, X509AlternativeNamesEnum.Rfc822Name);
        Assert.IsTrue(String.Equals(ext.AlternativeNames[2].Value, "email@company.com"));

        Assert.AreEqual(ext.AlternativeNames[3].Type, X509AlternativeNamesEnum.IpAddress);
        Assert.IsTrue(String.Equals(ext.AlternativeNames[3].Value, "192.168.2.56"));

        Assert.AreEqual(ext.AlternativeNames[4].Type, X509AlternativeNamesEnum.IpAddress);
        Assert.IsTrue(String.Equals(ext.AlternativeNames[4].Value, "2001:db8:85a3:8d3:1319:8a2e:370:7348"));

        Assert.AreEqual(ext.AlternativeNames[5].Type, X509AlternativeNamesEnum.RegisteredId);
        Assert.IsTrue(String.Equals(ext.AlternativeNames[5].Value, "1.3.6.1.4.1.311.25.1"));

        Assert.AreEqual(ext.AlternativeNames[6].Type, X509AlternativeNamesEnum.URL);
        Assert.IsTrue(String.Equals(ext.AlternativeNames[6].Value, "https://verisign.com/"));

        Assert.AreEqual(ext.AlternativeNames[7].Type, X509AlternativeNamesEnum.UserPrincipalName);
        Assert.AreEqual(ext.AlternativeNames[7].OID.Value, "1.3.6.1.4.1.311.20.2.3");
        Assert.IsTrue(String.Equals(ext.AlternativeNames[7].Value, "admin@contoso.com"));

        Assert.AreEqual(ext.AlternativeNames[8].Type, X509AlternativeNamesEnum.OtherName);
        Assert.AreEqual(ext.AlternativeNames[8].OID.Value, "1.3.56.7.45");
        Assert.IsTrue(String.Equals(ext.AlternativeNames[8].Value, "cf 47 97 f4 bd f3 4c 77 8e 05 11 84 c2 1b fb 79"));

        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.SAN);
    }
    [TestMethod]
    public void TestSANExtensionEncode() {
        //X509SubjectAlternativeNamesExtension alt = DecodeSANExtension();
        //var c = new X509AlternativeNameCollection();
        //foreach (var altName in alt.AlternativeNames) {
        //	c.Add(altName.OID != null
        //		? new X509AlternativeName(altName.Type, altName.Value, altName.OID)
        //		: new X509AlternativeName(altName.Type, altName.Value));
        //}
    }
    [TestMethod]
    public void TestSANEmptyExtensionDecode() {
        AsnEncodedData asn = new AsnEncodedData(Convert.FromBase64String(Extensions.NameConstraintsEmpty));
        var ext = new X509NameConstraintsExtension(asn);
        try {
            var san = new X509SubjectAlternativeNamesExtension(ext.PermittedSubtree, false);
            throw new Exception("Must throw failed.");
        } catch { }
        try {
            asn = new AsnEncodedData(ext.PermittedSubtree.Encode());
            var san2 = new X509SubjectAlternativeNamesExtension(asn, false);
            throw new Exception("Must throw failed2.");
        } catch { }
    }
    [TestMethod]
    public void TestCDP() {
        List<String> uris = new List<String> {
                                                     "http://ca.whitebearhome.com:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN=Whitebear Home CA,O=Whitebear Home,C=CA",
                                                     "http://ca.whitebearhome.com:8080/ejbca/publicweb/webdist/certdist?cmd=deltacrl&issuer=CN=Whitebear Home CA,O=Whitebear Home,C=CA"
                                                 };
        var cdp = new X509CRLDistributionPointsExtension(uris.ToArray());
        var cert = new X509Certificate2(Convert.FromBase64String(Resources.MultiCDP));
        X509Extension ex = null;
        foreach (var ext in cert.Extensions.Cast<X509Extension>().Where(ext => ext.Oid.Value == "2.5.29.31")) {
            ex = ext;
        }
        var cdp2 = new X509CRLDistributionPointsExtension(ex, false);
        var urllist = cdp2.GetURLs();

        var cert3 = new X509Certificate2(Convert.FromBase64String(Resources.CRLIssuer));
        X509Extension ex3 = null;
        foreach (var ext in cert3.Extensions.Cast<X509Extension>().Where(ext => ext.Oid.Value == "2.5.29.31")) {
            ex3 = ext;
        }
        var cdp3 = new X509CRLDistributionPointsExtension(ex3, false);
        var urllist3 = cdp3.GetURLs();
    }
    [TestMethod]
    public void TextNameConstraintsDecode() {
        AsnEncodedData asn = new AsnEncodedData(Convert.FromBase64String(Extensions.NameConstraints));
        X509NameConstraintsExtension ext = new X509NameConstraintsExtension(asn);
        Assert.IsTrue(ext.Critical, "Extension is not critical.");
        Assert.IsTrue(ext.Oid.Value == "2.5.29.30");

        Assert.AreEqual(ext.PermittedSubtree.Count, 11);
        Assert.AreEqual(ext.ExcludedSubtree.Count, 4);

        // permitted subtree
        Assert.AreEqual(ext.PermittedSubtree[0].Type, X509AlternativeNamesEnum.UserPrincipalName);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[0].Value, "administrator@sysadmins.lv", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.PermittedSubtree[1].Type, X509AlternativeNamesEnum.Rfc822Name);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[1].Value, "@sysadmins.lv", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.PermittedSubtree[2].Type, X509AlternativeNamesEnum.DnsName);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[2].Value, ".contoso.com", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.PermittedSubtree[3].Type, X509AlternativeNamesEnum.DirectoryName);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[3].Value, "DC=sysadmins, DC=LV", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.PermittedSubtree[4].Type, X509AlternativeNamesEnum.URL);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[4].Value, ".sysadmins.lv", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.PermittedSubtree[5].Type, X509AlternativeNamesEnum.URL);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[5].Value, "https://localhost/certsrv/default.html", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.PermittedSubtree[6].Type, X509AlternativeNamesEnum.URL);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[6].Value, "file://localhost/certsrv/default.html", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.PermittedSubtree[7].Type, X509AlternativeNamesEnum.IpAddress);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[7].Value, "10.1.0.172/21", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.PermittedSubtree[8].Type, X509AlternativeNamesEnum.IpAddress);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[8].Value, "::255.255.18.172/48", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.PermittedSubtree[9].Type, X509AlternativeNamesEnum.IpAddress);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[9].Value, "1234:5678:9abc:def0:3210:7654:ba98:fedc/41", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.PermittedSubtree[10].Type, X509AlternativeNamesEnum.IpAddress);
        Assert.IsTrue(String.Equals(ext.PermittedSubtree[10].Value, "1234::def0:3210:7654:ba98:fedc/128", StringComparison.OrdinalIgnoreCase));

        // excluded subtree
        Assert.AreEqual(ext.ExcludedSubtree[0].Type, X509AlternativeNamesEnum.UserPrincipalName);
        Assert.IsTrue(String.Equals(ext.ExcludedSubtree[0].Value, "@contoso.com", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.ExcludedSubtree[1].Type, X509AlternativeNamesEnum.Rfc822Name);
        Assert.IsTrue(String.Equals(ext.ExcludedSubtree[1].Value, "@contoso.com", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.ExcludedSubtree[2].Type, X509AlternativeNamesEnum.DirectoryName);
        Assert.IsTrue(String.Equals(ext.ExcludedSubtree[2].Value, "DC=contoso, DC=com", StringComparison.OrdinalIgnoreCase));

        Assert.AreEqual(ext.ExcludedSubtree[3].Type, X509AlternativeNamesEnum.URL);
        Assert.IsTrue(String.Equals(ext.ExcludedSubtree[3].Value, ".contoso.com", StringComparison.OrdinalIgnoreCase));
    }
    [TestMethod]
    public void TestNameConstraintsEmptyDecode() {
        AsnEncodedData asn = new AsnEncodedData(Convert.FromBase64String(Extensions.NameConstraintsEmpty));
        var ext = new X509NameConstraintsExtension(asn);
        Assert.IsTrue(ext.Critical, "Extension is not critical.");
        Assert.IsTrue(ext.Oid.Value == "2.5.29.30");
    }
    [TestMethod]
    public void TestNameConstraintsEncode() {
        var permittedSubTree = new X509AlternativeNameCollection();
        var excludedSubTree = new X509AlternativeNameCollection();
        excludedSubTree.Add(new X509AlternativeName(X509AlternativeNamesEnum.DnsName, "example.com"));
        var ns = new X509NameConstraintsExtension(permittedSubTree, excludedSubTree);
        Assert.AreEqual(0, ns.PermittedSubtree.Count);
        Assert.AreEqual(1, ns.ExcludedSubtree.Count);
        var rw = ns.Encode();
        var asn = new AsnEncodedData(X509ExtensionOid.NameConstraints, ns.RawData);
        ns = new X509NameConstraintsExtension(asn);
        Assert.AreEqual(0, ns.PermittedSubtree.Count);
        Assert.AreEqual(1, ns.ExcludedSubtree.Count);
    }
    [TestMethod]
    public void TestCertPolicyConstraintsDecode() {
        AsnEncodedData asn = new AsnEncodedData(Convert.FromBase64String(Extensions.CertPolicyConstraintsFull));
        var ext = new X509CertificatePolicyConstraintsExtension(asn);
        Assert.IsTrue(ext.Critical);
        Assert.AreEqual(ext.Oid.Value, "2.5.29.36");

        // full
        Assert.AreEqual(ext.RequireExplicitPolicy, 3);
        Assert.AreEqual(ext.InhibitPolicyMapping, 5);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.CertPolicyConstraintsFull);

        // inhibit only
        asn = new AsnEncodedData(Convert.FromBase64String(Extensions.CertPolicyConstraintsInhibit));
        ext = new X509CertificatePolicyConstraintsExtension(asn);
        Assert.IsNull(ext.RequireExplicitPolicy);
        Assert.AreEqual(ext.InhibitPolicyMapping, 5);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.CertPolicyConstraintsInhibit);

        // required only
        asn = new AsnEncodedData(Convert.FromBase64String(Extensions.CertPolicyConstraintsRequired));
        ext = new X509CertificatePolicyConstraintsExtension(asn);
        Assert.AreEqual(ext.RequireExplicitPolicy, 3);
        Assert.IsNull(ext.InhibitPolicyMapping);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.CertPolicyConstraintsRequired);
    }
    [TestMethod]
    public void TestCertPolicyConstraintsEncode() {
        var ext = new X509CertificatePolicyConstraintsExtension(3, 5);
        Assert.IsTrue(ext.Critical);
        Assert.AreEqual(ext.Oid.Value, "2.5.29.36");

        // full
        Assert.AreEqual(ext.RequireExplicitPolicy, 3);
        Assert.AreEqual(ext.InhibitPolicyMapping, 5);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.CertPolicyConstraintsFull);

        // inhibit only
        ext = new X509CertificatePolicyConstraintsExtension(null, 5);
        Assert.IsNull(ext.RequireExplicitPolicy);
        Assert.AreEqual(ext.InhibitPolicyMapping, 5);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.CertPolicyConstraintsInhibit);

        // required only
        ext = new X509CertificatePolicyConstraintsExtension(3, null);
        Assert.AreEqual(ext.RequireExplicitPolicy, 3);
        Assert.IsNull(ext.InhibitPolicyMapping);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.CertPolicyConstraintsRequired);
    }
    [TestMethod]
    public void TestCertPolicyMappingsDecode() {
        AsnEncodedData asn = new AsnEncodedData(Convert.FromBase64String(Extensions.CertPolicyMappings));
        var ext = new X509CertificatePolicyMappingsExtension(asn);
        Assert.IsTrue(ext.Critical);
        Assert.AreEqual(ext.Oid.Value, "2.5.29.33");

        Assert.AreEqual(ext.OidMappings.Count, 2);
        Assert.AreEqual(ext.OidMappings[0].IssuerDomainOid.Value, "1.3.6.1.4.1.311.21.53");
        Assert.AreEqual(ext.OidMappings[0].SubjectDomainOid.Value, "1.2.3.4.87");
        Assert.AreEqual(ext.OidMappings[1].IssuerDomainOid.Value, "1.3.6.1.4.1.311.21.54");
        Assert.AreEqual(ext.OidMappings[1].SubjectDomainOid.Value, "1.2.3.4.89");

        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.CertPolicyMappings);
    }
    [TestMethod]
    public void TestCertPolicyMappingsEncode() {
        List<OidMapping> oids = new List<OidMapping>();
        oids.Add(new OidMapping(new Oid("1.3.6.1.4.1.311.21.53"), new Oid("1.2.3.4.87")));
        oids.Add(new OidMapping(new Oid("1.3.6.1.4.1.311.21.54"), new Oid("1.2.3.4.89")));
        var ext = new X509CertificatePolicyMappingsExtension(oids.ToArray());
        Assert.IsTrue(ext.Critical);
        Assert.AreEqual(ext.Oid.Value, "2.5.29.33");

        Assert.AreEqual(ext.OidMappings.Count, 2);
        Assert.AreEqual(ext.OidMappings[0].IssuerDomainOid.Value, "1.3.6.1.4.1.311.21.53");
        Assert.AreEqual(ext.OidMappings[0].SubjectDomainOid.Value, "1.2.3.4.87");
        Assert.AreEqual(ext.OidMappings[1].IssuerDomainOid.Value, "1.3.6.1.4.1.311.21.54");
        Assert.AreEqual(ext.OidMappings[1].SubjectDomainOid.Value, "1.2.3.4.89");

        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.CertPolicyMappings);
    }
    [TestMethod]
    public void TestAppPolicyConstraintsDecode() {
        AsnEncodedData asn = new AsnEncodedData(Convert.FromBase64String(Extensions.AppPolicyConstraintsFull));
        var ext = new X509ApplicationPolicyConstraintsExtension(asn);
        Assert.IsTrue(ext.Critical);
        Assert.AreEqual(ext.Oid.Value, "1.3.6.1.4.1.311.21.12");

        // full
        Assert.AreEqual(ext.RequireExplicitPolicy, 6);
        Assert.AreEqual(ext.InhibitPolicyMapping, 10);

        // inhibit only
        asn = new AsnEncodedData(Convert.FromBase64String(Extensions.AppPolicyConstraintsInhibit));
        ext = new X509ApplicationPolicyConstraintsExtension(asn);
        Assert.IsNull(ext.RequireExplicitPolicy);
        Assert.AreEqual(ext.InhibitPolicyMapping, 10);

        // required only
        asn = new AsnEncodedData(Convert.FromBase64String(Extensions.AppPolicyConstratinsRequired));
        ext = new X509ApplicationPolicyConstraintsExtension(asn);
        Assert.AreEqual(ext.RequireExplicitPolicy, 6);
        Assert.IsNull(ext.InhibitPolicyMapping);
    }
    [TestMethod]
    public void TestAppPolicyConstraintsEncode() {
        var ext = new X509ApplicationPolicyConstraintsExtension(6, 10);
        Assert.IsTrue(ext.Critical);
        Assert.AreEqual(ext.Oid.Value, "1.3.6.1.4.1.311.21.12");

        // full
        Assert.AreEqual(ext.RequireExplicitPolicy, 6);
        Assert.AreEqual(ext.InhibitPolicyMapping, 10);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.AppPolicyConstraintsFull);

        // inhibit only
        ext = new X509ApplicationPolicyConstraintsExtension(null, 10);
        Assert.IsNull(ext.RequireExplicitPolicy);
        Assert.AreEqual(ext.InhibitPolicyMapping, 10);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.AppPolicyConstraintsInhibit);

        // required only
        ext = new X509ApplicationPolicyConstraintsExtension(6, null);
        Assert.AreEqual(ext.RequireExplicitPolicy, 6);
        Assert.IsNull(ext.InhibitPolicyMapping);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.AppPolicyConstratinsRequired);
    }
    [TestMethod]
    public void TestAppPolicyMappingsDecode() {
        AsnEncodedData asn = new AsnEncodedData(Convert.FromBase64String(Extensions.AppPolicyMappings));
        var ext = new X509ApplicationPolicyMappingsExtension(asn);
        Assert.IsTrue(ext.Critical);
        Assert.AreEqual(ext.Oid.Value, "1.3.6.1.4.1.311.21.11");

        Assert.AreEqual(ext.OidMappings.Count, 2);
        Assert.AreEqual(ext.OidMappings[0].IssuerDomainOid.Value, "1.3.6.1.4.1.311.21.64");
        Assert.AreEqual(ext.OidMappings[0].SubjectDomainOid.Value, "1.2.3.4.98");
        Assert.AreEqual(ext.OidMappings[1].IssuerDomainOid.Value, "1.3.6.1.4.1.311.21.65");
        Assert.AreEqual(ext.OidMappings[1].SubjectDomainOid.Value, "1.2.3.4.100");

        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.AppPolicyMappings);
    }
    [TestMethod]
    public void TestAppPolicyMappingsEncode() {
        AsnEncodedData asn = new AsnEncodedData(Convert.FromBase64String(Extensions.AppPolicyMappings));
        var ext = new X509ApplicationPolicyMappingsExtension(asn);
        Assert.IsTrue(ext.Critical);
        Assert.AreEqual(ext.Oid.Value, "1.3.6.1.4.1.311.21.11");

        Assert.AreEqual(ext.OidMappings.Count, 2);
        Assert.AreEqual(ext.OidMappings[0].IssuerDomainOid.Value, "1.3.6.1.4.1.311.21.64");
        Assert.AreEqual(ext.OidMappings[0].SubjectDomainOid.Value, "1.2.3.4.98");
        Assert.AreEqual(ext.OidMappings[1].IssuerDomainOid.Value, "1.3.6.1.4.1.311.21.65");
        Assert.AreEqual(ext.OidMappings[1].SubjectDomainOid.Value, "1.2.3.4.100");

        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.AppPolicyMappings);
    }
    [TestMethod]
    public void TestAkiDecode() {
        AsnEncodedData asn = new AsnEncodedData(Convert.FromBase64String(Extensions.AKIIssuerSerial));
        var ext = new X509AuthorityKeyIdentifierExtension(asn, false);
        Assert.IsFalse(ext.Critical);
        Assert.AreEqual(ext.Oid.Value, "2.5.29.35");
        // IssuerNames + serial number
        Assert.IsFalse((ext.IncludedComponents & AuthorityKeyIdentifierType.KeyIdentifier) > 0);
        Assert.IsTrue((ext.IncludedComponents & AuthorityKeyIdentifierType.AlternativeNames) > 0);
        Assert.IsTrue((ext.IncludedComponents & AuthorityKeyIdentifierType.SerialNumber) > 0);
        Assert.AreEqual(X509AlternativeNamesEnum.DirectoryName, ext.IssuerNames[0].Type);
        Assert.AreEqual("CN=Hongkong Post Root CA 1, O=Hongkong Post, C=HK", ext.IssuerNames[0].Value);
        Assert.AreEqual("03e8", ext.SerialNumber);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.AKIIssuerSerial);

        // keyId
        asn = new AsnEncodedData(Convert.FromBase64String(Extensions.AkiKeyId));
        ext = new X509AuthorityKeyIdentifierExtension(asn, false);
        Assert.IsTrue((ext.IncludedComponents & AuthorityKeyIdentifierType.KeyIdentifier) > 0);
        Assert.IsFalse((ext.IncludedComponents & AuthorityKeyIdentifierType.AlternativeNames) > 0);
        Assert.IsFalse((ext.IncludedComponents & AuthorityKeyIdentifierType.SerialNumber) > 0);
        Assert.AreEqual("9dfdfcaac5bb26e2c49ad5d04b5d6a610a8aba43", ext.KeyIdentifier);
        Assert.IsNull(ext.IssuerNames);
        Assert.IsNull(ext.SerialNumber);
        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.AkiKeyId);
    }
    [TestMethod]
    public void TestCrossCertDp() {
        AsnEncodedData asn = new AsnEncodedData(Convert.FromBase64String(Extensions.CrossCertDistrPoint));
        var ext = new X509CrossCertificateDistributionPointsExtension(asn, false);
        Assert.IsFalse(ext.Critical);
        Assert.AreEqual(ext.Oid.Value, "1.3.6.1.4.1.311.10.9.1");

        Assert.IsNotNull(ext.DeltaSyncTimeInSeconds);
        Assert.AreEqual(24, ext.DeltaSyncTimeInSeconds);

        Assert.AreEqual(Convert.ToBase64String(ext.RawData), Extensions.CrossCertDistrPoint);
    }
    [TestMethod]
    public void TestNextCrlPublishEncode() {
        var dt = new DateTime(2010, 04, 18, 14, 21, 44);
        var ext = new X509NextCRLPublishExtension(dt, false);
        var ext2 = new X509NextCRLPublishExtension(new AsnEncodedData(ext.RawData), false);
        Assert.AreEqual(ext.NextCRLPublish, ext2.NextCRLPublish);
    }
    [TestMethod]
    public void TestNextCrlPublishDecode() {
        var bytes = Convert.FromBase64String(Resources.BaseCRLv2);
        var crl = new X509CRL2(bytes);
        X509NextCRLPublishExtension ext = (X509NextCRLPublishExtension)crl.Extensions["1.3.6.1.4.1.311.21.4"];
        Assert.AreEqual(new DateTime(2010, 04, 18, 14, 21, 44), ext.NextCRLPublish);
    }
    [TestMethod]
    public void TestCAVersionDecode() {
        // v0.0 full version
        var bytes = new Byte[] { 2, 4, 0, 0, 0, 0 };
        var asn = new AsnEncodedData(bytes);
        var caVersion = new X509CAVersionExtension(asn, false);
        Assert.AreEqual(0, caVersion.CACertificateVersion);
        Assert.AreEqual(0, caVersion.CAKeyVersion);
        Assert.AreEqual("V0.0", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        // v0.0 short version
        bytes = new Byte[] { 2, 1, 0 };
        asn = new AsnEncodedData(bytes);
        caVersion = new X509CAVersionExtension(asn, true);
        Assert.AreEqual(0, caVersion.CACertificateVersion);
        Assert.AreEqual(0, caVersion.CAKeyVersion);
        Assert.AreEqual("V0.0", caVersion.Format(false));
        Assert.IsTrue(caVersion.Critical);

        // v1.0 short version
        bytes = new Byte[] { 2, 1, 1 };
        asn = new AsnEncodedData(bytes);
        caVersion = new X509CAVersionExtension(asn, false);
        Assert.AreEqual(1, caVersion.CACertificateVersion);
        Assert.AreEqual(0, caVersion.CAKeyVersion);
        Assert.AreEqual("V1.0", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        // v257.0 full version
        bytes = new Byte[] { 2, 4, 0, 0, 1, 1 };
        asn = new AsnEncodedData(bytes);
        caVersion = new X509CAVersionExtension(asn, false);
        Assert.AreEqual(257, caVersion.CACertificateVersion);
        Assert.AreEqual(0, caVersion.CAKeyVersion);
        Assert.AreEqual("V257.0", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        // v257.0 short version
        bytes = new Byte[] { 2, 2, 1, 1 };
        asn = new AsnEncodedData(bytes);
        caVersion = new X509CAVersionExtension(asn, false);
        Assert.AreEqual(257, caVersion.CACertificateVersion);
        Assert.AreEqual(0, caVersion.CAKeyVersion);
        Assert.AreEqual("V257.0", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        // v1.1 full version
        bytes = new Byte[] { 2, 4, 0, 1, 0, 1 };
        asn = new AsnEncodedData(bytes);
        caVersion = new X509CAVersionExtension(asn, false);
        Assert.AreEqual(1, caVersion.CACertificateVersion);
        Assert.AreEqual(1, caVersion.CAKeyVersion);
        Assert.AreEqual("V1.1", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        // v1.1 shorter version
        bytes = new Byte[] { 2, 3, 1, 0, 1 };
        asn = new AsnEncodedData(bytes);
        caVersion = new X509CAVersionExtension(asn, true);
        Assert.AreEqual(1, caVersion.CACertificateVersion);
        Assert.AreEqual(1, caVersion.CAKeyVersion);
        Assert.AreEqual("V1.1", caVersion.Format(false));
        Assert.IsTrue(caVersion.Critical);

        // v256.256 full/short version
        bytes = new Byte[] { 2, 4, 1, 0, 1, 0 };
        asn = new AsnEncodedData(bytes);
        caVersion = new X509CAVersionExtension(asn, false);
        Assert.AreEqual(256, caVersion.CACertificateVersion);
        Assert.AreEqual(256, caVersion.CAKeyVersion);
        Assert.AreEqual("V256.256", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        // v256.256 full/short version
        bytes = new Byte[] { 2, 4, 255, 253, 255, 254 };
        asn = new AsnEncodedData(bytes);
        caVersion = new X509CAVersionExtension(asn, false);
        Assert.AreEqual(UInt16.MaxValue - 1, caVersion.CACertificateVersion);
        Assert.AreEqual(UInt16.MaxValue - 2, caVersion.CAKeyVersion);
        Assert.AreEqual("V65534.65533", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);
    }

    [TestMethod]
    public void TestCAVersionEncode() {
        var caVersion = new X509CAVersionExtension(0, 0, false);
        Assert.IsTrue(caVersion.RawData.SequenceEqual(new Byte[] { 2, 1, 0 }));
        Assert.AreEqual("V0.0", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        caVersion = new X509CAVersionExtension(0, 0, true);
        Assert.IsTrue(caVersion.RawData.SequenceEqual(new Byte[] { 2, 1, 0 }));
        Assert.AreEqual("V0.0", caVersion.Format(false));
        Assert.IsTrue(caVersion.Critical);

        caVersion = new X509CAVersionExtension(1, 0, false);
        Assert.IsTrue(caVersion.RawData.SequenceEqual(new Byte[] { 2, 1, 1 }));
        Assert.AreEqual("V1.0", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        caVersion = new X509CAVersionExtension(257, 0, false);
        Assert.IsTrue(caVersion.RawData.SequenceEqual(new Byte[] { 2, 2, 1, 1 }));
        Assert.AreEqual("V257.0", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        caVersion = new X509CAVersionExtension(1, 1, false);
        Assert.IsTrue(caVersion.RawData.SequenceEqual(new Byte[] { 2, 3, 1, 0, 1 }));
        Assert.AreEqual("V1.1", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        caVersion = new X509CAVersionExtension(256, 256, true);
        Assert.IsTrue(caVersion.RawData.SequenceEqual(new Byte[] { 2, 4, 1, 0, 1, 0 }));
        Assert.AreEqual("V256.256", caVersion.Format(false));
        Assert.IsTrue(caVersion.Critical);

        caVersion = new X509CAVersionExtension(UInt16.MaxValue, UInt16.MaxValue, false);
        Assert.IsTrue(caVersion.RawData.SequenceEqual(new Byte[] { 2, 4, 255, 255, 255, 255 }));
        Assert.AreEqual("V65535.65535", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);

        caVersion = new X509CAVersionExtension(UInt16.MaxValue - 1, UInt16.MaxValue - 2, false);
        Assert.IsTrue(caVersion.RawData.SequenceEqual(new Byte[] { 2, 4, 255, 253, 255, 254 }));
        Assert.AreEqual("V65534.65533", caVersion.Format(false));
        Assert.IsFalse(caVersion.Critical);
    }

    [TestMethod]
    public void TestIDP() {
        var asnData = new AsnEncodedData(Convert.FromBase64String(Resources.Extension_IDP));
        var idpExt1 = new X509IssuingDistributionPointsExtension(asnData, true);
        Assert.IsNotNull(idpExt1.DistributionPoint);
        Assert.AreEqual(X509RevocationReasonFlag.None, idpExt1.Reasons);
        Assert.IsFalse(idpExt1.OnlyCaCerts);
        Assert.IsFalse(idpExt1.OnlyUserCerts);
        Assert.IsFalse(idpExt1.OnlyAttributeCerts);
        Assert.IsFalse(idpExt1.IndirectCRL);
        String txt1 = idpExt1.Format(true);
        Debug.WriteLine(txt1);

        var idpPoint = new X509DistributionPoint(new[] { new Uri("http://www.sysadmins.lv/pki/evca-2.crl") });

        var idpExt2 = new X509IssuingDistributionPointsExtension(idpPoint);
        Assert.IsNotNull(idpExt1.DistributionPoint);
        Assert.AreEqual("http://www.sysadmins.lv/pki/evca-2.crl", idpExt2.DistributionPoint.FullName[0].Value);
        Assert.AreEqual(X509RevocationReasonFlag.None, idpExt1.Reasons);
        Assert.IsFalse(idpExt1.OnlyCaCerts);
        Assert.IsFalse(idpExt1.OnlyUserCerts);
        Assert.IsFalse(idpExt1.OnlyAttributeCerts);
        Assert.IsFalse(idpExt1.IndirectCRL);
        String txt2 = idpExt2.Format(true);
        Assert.AreEqual(txt2, txt1);

        idpExt2 = new X509IssuingDistributionPointsExtension(idpPoint, false, X509RevocationReasonFlag.CACompromise | X509RevocationReasonFlag.CeaseOfOperation);
        Assert.IsNotNull(idpExt2.DistributionPoint);
        Assert.AreEqual(X509RevocationReasonFlag.CACompromise | X509RevocationReasonFlag.CeaseOfOperation, idpExt2.Reasons);
        Debug.WriteLine("IDP Reasons:");
        Debug.WriteLine(idpExt2.Format(true));

        idpExt2 = new X509IssuingDistributionPointsExtension(idpPoint, true);
        Assert.IsNotNull(idpExt2.DistributionPoint);
        Assert.IsTrue(idpExt2.IndirectCRL);
        Debug.WriteLine("Indirect CRL:");
        Debug.WriteLine(idpExt2.Format(true));

        idpExt2 = new X509IssuingDistributionPointsExtension(idpPoint, false, X509RevocationReasonFlag.None, IssuingDistributionPointScope.OnlyCaCerts);
        Assert.IsNotNull(idpExt2.DistributionPoint);
        Assert.IsTrue(idpExt2.OnlyCaCerts);
        Debug.WriteLine("Only CA certs:");
        Debug.WriteLine(idpExt2.Format(true));

        idpExt2 = new X509IssuingDistributionPointsExtension(idpPoint, false, X509RevocationReasonFlag.None, IssuingDistributionPointScope.OnlyUserCerts);
        Assert.IsNotNull(idpExt2.DistributionPoint);
        Assert.IsTrue(idpExt2.OnlyUserCerts);
        Debug.WriteLine("Only User certs:");
        Debug.WriteLine(idpExt2.Format(true));

        idpExt2 = new X509IssuingDistributionPointsExtension(idpPoint, false, X509RevocationReasonFlag.None, IssuingDistributionPointScope.OnlyAttributeCerts);
        Assert.IsNotNull(idpExt2.DistributionPoint);
        Assert.IsTrue(idpExt2.OnlyAttributeCerts);
        Debug.WriteLine("Only Attribute certs:");
        Debug.WriteLine(idpExt2.Format(true));
    }
}
