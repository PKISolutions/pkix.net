using Interop.CERTENROLLLib;
// ReSharper disable SuspiciousTypeConversion.Global

namespace SysadminsLV.PKI.Dcom.Implementations;

static class CertEnrollFactory {
    public static CAlternativeName CreateAlternativeName() {
        return new CAlternativeName();
    }
    public static CAlternativeNames CreateAlternativeNames() {
        return new CAlternativeNames();
    }
    public static CBinaryConverter CreateBinaryConverter() {
        return new CBinaryConverter();
    }
    public static CCertificateAttestationChallenge CreateCertificateAttestationChallenge() {
        return new CCertificateAttestationChallenge();
    }
    public static CCertificatePolicies CreateCertificatePolicies() {
        return new CCertificatePolicies();
    }
    public static CCertificatePolicy CreateCertificatePolicy() {
        return new CCertificatePolicy();
    }
    public static CCertProperties CreateCertProperties() {
        return new CCertProperties();
    }
    public static CCertPropertyArchived CreateCertPropertyArchived() {
        return new CCertPropertyArchived();
    }
    public static CCertPropertyArchivedKeyHash CreateCertPropertyArchivedKeyHash() {
        return new CCertPropertyArchivedKeyHash();
    }
    public static CCertPropertyAutoEnroll CreateCertPropertyAutoEnroll() {
        return new CCertPropertyAutoEnroll();
    }
    public static CCertPropertyBackedUp CreateCertPropertyBackedUp() {
        return new CCertPropertyBackedUp();
    }
    public static CCertProperty CreateCertProperty() {
        return new CCertProperty();
    }
    public static CCertPropertyDescription CreateCertPropertyDescription() {
        return new CCertPropertyDescription();
    }
    public static CCertPropertyEnrollment CreateCertPropertyEnrollment() {
        return new CCertPropertyEnrollment();
    }
    public static CCertPropertyEnrollmentPolicyServer CreateCertPropertyEnrollmentPolicyServer() {
        return new CCertPropertyEnrollmentPolicyServer();
    }
    public static CCertPropertyFriendlyName CreateCertPropertyFriendlyName() {
        return new CCertPropertyFriendlyName();
    }
    public static CCertPropertyKeyProvInfo CreateCertPropertyKeyProvInfo() {
        return new CCertPropertyKeyProvInfo();
    }
    public static CCertPropertyRenewal CreateCertPropertyRenewal() {
        return new CCertPropertyRenewal();
    }
    public static CCertPropertyRequestOriginator CreateCertPropertyRequestOriginator() {
        return new CCertPropertyRequestOriginator();
    }
    public static CCertPropertySHA1Hash CreateCertPropertySHA1Hash() {
        return new CCertPropertySHA1Hash();
    }
    public static CCryptAttribute CreateCryptAttribute() {
        return new CCryptAttribute();
    }
    public static CCryptAttributes CreateCryptAttributes() {
        return new CCryptAttributes();
    }
    public static CCspInformation CreateCspInformation() {
        return new CCspInformation();
    }
    public static CCspInformations CreateCspInformations() {
        return new CCspInformations();
    }
    public static CCspStatus CreateCspStatus() {
        return new CCspStatus();
    }
    public static CObjectId CreateObjectId() {
        return new CObjectId();
    }
    public static CObjectIds CreateObjectIds() {
        return new CObjectIds();
    }
    public static CPolicyQualifier CreatePolicyQualifier() {
        return new CPolicyQualifier();
    }
    public static CPolicyQualifiers CreatePolicyQualifiers() {
        return new CPolicyQualifiers();
    }
    public static CSignerCertificate CreateSignerCertificate() {
        return new CSignerCertificate();
    }
    public static CSmimeCapabilities CreateSmimeCapabilities() {
        return new CSmimeCapabilities();
    }
    public static CSmimeCapability CreateSmimeCapability() {
        return new CSmimeCapability();
    }
    public static CX500DistinguishedName CreateX500DistinguishedName() {
        return new CX500DistinguishedName();
    }
    public static CX509AttributeArchiveKey CreateX509AttributeArchiveKey() {
        return new CX509AttributeArchiveKey();
    }
    public static CX509AttributeArchiveKeyHash CreateX509AttributeArchiveKeyHash() {
        return new CX509AttributeArchiveKeyHash();
    }
    public static CX509Attribute CreateX509Attribute() {
        return new CX509Attribute();
    }
    public static CX509AttributeClientId CreateX509AttributeClientId() {
        return new CX509AttributeClientId();
    }
    public static CX509AttributeCspProvider CreateX509AttributeCspProvider() {
        return new CX509AttributeCspProvider();
    }
    public static CX509AttributeExtensions CreateX509AttributeExtensions() {
        return new CX509AttributeExtensions();
    }
    public static CX509AttributeOSVersion CreateX509AttributeOSVersion() {
        return new CX509AttributeOSVersion();
    }
    public static CX509AttributeRenewalCertificate CreateX509AttributeRenewalCertificate() {
        return new CX509AttributeRenewalCertificate();
    }
    public static CX509Attributes CreateX509Attributes() {
        return new CX509Attributes();
    }
    public static CX509CertificateRequestCertificate CreateX509CertificateRequestCertificate() {
        return new CX509CertificateRequestCertificate();
    }
    public static CX509CertificateRequestCmc CreateX509CertificateRequestCmc() {
        return new CX509CertificateRequestCmc();
    }
    public static CX509CertificateRequestPkcs10 CreateX509CertificateRequestPkcs10() {
        return new CX509CertificateRequestPkcs10();
    }
    public static CX509CertificateRequestPkcs7 CreateX509CertificateRequestPkcs7() {
        return new CX509CertificateRequestPkcs7();
    }
    public static CX509CertificateRevocationList CreateX509CertificateRevocationList() {
        return new CX509CertificateRevocationList();
    }
    public static CX509CertificateRevocationListEntries CreateX509CertificateRevocationListEntries() {
        return new CX509CertificateRevocationListEntries();
    }
    public static CX509CertificateRevocationListEntry CreateX509CertificateRevocationListEntry() {
        return new CX509CertificateRevocationListEntry();
    }
    public static CX509CertificateTemplateADWritable CreateX509CertificateTemplateADWritable() {
        return new CX509CertificateTemplateADWritable();
    }
    public static CX509EndorsementKey CreateX509EndorsementKey() {
        return new CX509EndorsementKey();
    }
    public static CX509Enrollment CreateX509Enrollment() {
        return new CX509Enrollment();
    }
    public static CX509EnrollmentHelper CreateX509EnrollmentHelper() {
        return new CX509EnrollmentHelper();
    }
    public static CX509EnrollmentPolicyActiveDirectory CreateX509EnrollmentPolicyActiveDirectory() {
        return new CX509EnrollmentPolicyActiveDirectory();
    }
    public static CX509EnrollmentPolicyWebService CreateX509EnrollmentPolicyWebService() {
        return new CX509EnrollmentPolicyWebService();
    }
    public static CX509EnrollmentWebClassFactory CreateX509EnrollmentWebClassFactory() {
        return new CX509EnrollmentWebClassFactory();
    }
    public static CX509ExtensionAlternativeNames CreateX509ExtensionAlternativeNames() {
        return new CX509ExtensionAlternativeNames();
    }
    public static CX509ExtensionAuthorityKeyIdentifier CreateX509ExtensionAuthorityKeyIdentifier() {
        return new CX509ExtensionAuthorityKeyIdentifier();
    }
    public static CX509ExtensionBasicConstraints CreateX509ExtensionBasicConstraints() {
        return new CX509ExtensionBasicConstraints();
    }
    public static CX509ExtensionCertificatePolicies CreateX509ExtensionCertificatePolicies() {
        return new CX509ExtensionCertificatePolicies();
    }
    public static CX509Extension CreateX509Extension() {
        return new CX509Extension();
    }
    public static CX509ExtensionEnhancedKeyUsage CreateX509ExtensionEnhancedKeyUsage() {
        return new CX509ExtensionEnhancedKeyUsage();
    }
    public static CX509ExtensionKeyUsage CreateX509ExtensionKeyUsage() {
        return new CX509ExtensionKeyUsage();
    }
    public static CX509ExtensionMSApplicationPolicies CreateX509ExtensionMSApplicationPolicies() {
        return new CX509ExtensionMSApplicationPolicies();
    }
    public static CX509Extensions CreateX509Extensions() {
        return new CX509Extensions();
    }
    public static CX509ExtensionSmimeCapabilities CreateX509ExtensionSmimeCapabilities() {
        return new CX509ExtensionSmimeCapabilities();
    }
    public static CX509ExtensionSubjectKeyIdentifier CreateX509ExtensionSubjectKeyIdentifier() {
        return new CX509ExtensionSubjectKeyIdentifier();
    }
    public static CX509ExtensionTemplate CreateX509ExtensionTemplate() {
        return new CX509ExtensionTemplate();
    }
    public static CX509ExtensionTemplateName CreateX509ExtensionTemplateName() {
        return new CX509ExtensionTemplateName();
    }
    public static CX509MachineEnrollmentFactory CreateX509MachineEnrollmentFactory() {
        return new CX509MachineEnrollmentFactory();
    }
    public static CX509NameValuePair CreateX509NameValuePair() {
        return new CX509NameValuePair();
    }
    public static CX509PolicyServerListManager CreateX509PolicyServerListManager() {
        return new CX509PolicyServerListManager();
    }
    public static CX509PolicyServerUrl CreateX509PolicyServerUrl() {
        return new CX509PolicyServerUrl();
    }
    public static CX509PrivateKey CreateX509PrivateKey() {
        return new CX509PrivateKey();
    }
    public static CX509PublicKey CreateX509PublicKey() {
        return new CX509PublicKey();
    }
    public static CX509SCEPEnrollment CreateX509SCEPEnrollment() {
        return new CX509SCEPEnrollment();
    }
}
