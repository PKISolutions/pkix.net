using System.Runtime.InteropServices;
using System.Text;
using PKI.Exceptions;
using PKI.OCSP;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Utils.CLRExtensions;
using static PKI.Structs.Wincrypt;

namespace System.Security.Cryptography.X509Certificates;

/// <summary>
/// Represents certificate context property object in the certificate store.
/// </summary>
/// <remarks>
/// No public constructors are defined. Objects of this class are created by calling
/// <see cref="X509Certificate2Extensions.GetCertificateContextProperty"/> or
/// <see cref="X509Certificate2Extensions.GetCertificateContextProperties"/> extension methods.
/// </remarks>
public class X509CertificateContextProperty {

    internal X509CertificateContextProperty(X509Certificate2 cert, X509CertificatePropertyType propID) {
        if (IntPtr.Zero.Equals(cert.Handle)) { throw new UninitializedObjectException(); }
        Certificate = cert;
        PropertyName = propID;
    }
    internal X509CertificateContextProperty(X509Certificate2 cert, X509CertificatePropertyType propID, Byte[] bytes)
        : this(cert, propID) {
        switch (propID) {
            // DWORD
            case X509CertificatePropertyType.AccessState:
            case X509CertificatePropertyType.KeySpec:
            case X509CertificatePropertyType.PublicKeyLength:
            case X509CertificatePropertyType.PublicKeyCngLength:
                initializeDword(bytes);
                break;
            // string
            case X509CertificatePropertyType.CNGSignatureHashAlgorithm:
            case X509CertificatePropertyType.PvkFile:
            case X509CertificatePropertyType.FriendlyName:
            case X509CertificatePropertyType.Description:
            case X509CertificatePropertyType.AutoenrollmentTemplateName:
            case X509CertificatePropertyType.StatusInfo:
            case X509CertificatePropertyType.RequestOriginatorMachine:
            case X509CertificatePropertyType.SourceLocation:
            case X509CertificatePropertyType.SourceUrl:
            case X509CertificatePropertyType.OcspCachePrefix:
                initializeString(bytes);
                break;
            // ASN.1
            case X509CertificatePropertyType.EnhancedKeyUsage:
            case X509CertificatePropertyType.RootProgramCertificatePolicies:
            case X509CertificatePropertyType.CTLNextUpdateLocation:
            case X509CertificatePropertyType.OcspResponse:
                initializeAsn1(bytes);
                break;
            case X509CertificatePropertyType.CEPEnrollmentInfo:
            case X509CertificatePropertyType.EnrollmentInfo:
                initializeStruct(bytes);
                break;
            case X509CertificatePropertyType.Archived:
                UnderlyingType = typeof(Boolean);
                PropertyValue = true;
                break;
            // byte[]
            default:
                initializeHash(bytes);
                break;
        }
    }
    internal X509CertificateContextProperty(X509Certificate2 cert, X509CertificatePropertyType propID, IntPtr data)
        : this(cert, propID) {
        initializeStruct(data);
    }

    /// <summary>
    /// Gets the certificate the property is associated with.
    /// </summary>
    public X509Certificate2 Certificate { get; }
    /// <summary>
    /// Gets the certificate property name.
    /// </summary>
    public X509CertificatePropertyType PropertyName { get; }
    /// <summary>
    /// Gets the certificate property value. The type of the value is determined by a <see cref="UnderlyingType"/>
    /// property.
    /// </summary>
    public Object PropertyValue { get; private set; }
    /// <summary>
    /// Gets the type of the value stored in the <see cref="PropertyValue"/> property.
    /// </summary>
    public Type UnderlyingType { get; private set; }
        
    void initializeHash(Byte[] bytes) {
        UnderlyingType = typeof(String);
        PropertyValue = bytes.Length == 0
            ? null
            : AsnFormatter.BinaryToString(bytes, EncodingType.Hex, EncodingFormat.NOCRLF);
    }
    void initializeString(Byte[] bytes) {
        UnderlyingType = typeof(String);
        PropertyValue = Encoding.Unicode.GetString(bytes).TrimEnd('\0');
    }
    void initializeDword(Byte[] bytes) {
        switch (PropertyName) {
            case X509CertificatePropertyType.AccessState:
                UnderlyingType = typeof(CertificateStoreObjectAccessStateEnum);
                Int32 flags = BitConverter.ToInt32(bytes, 0);
                PropertyValue = (CertificateStoreObjectAccessStateEnum)flags;
                break;
            case X509CertificatePropertyType.InsertTimeStamp:
                UnderlyingType = typeof(DateTime);
                Int64 fileTime = BitConverter.ToInt64(bytes, 0);
                PropertyValue = DateTime.FromFileTimeUtc(fileTime);
                break;
            default:
                UnderlyingType = typeof(Int32);
                PropertyValue = BitConverter.ToInt32(bytes, 0);
                break;
        }
    }

    void initializeAsn1(Byte[] bytes) {
        switch (PropertyName) {
            case X509CertificatePropertyType.EnhancedKeyUsage:
                UnderlyingType = typeof(X509EnhancedKeyUsageExtension);
                AsnEncodedData asn = new AsnEncodedData(bytes);
                PropertyValue = new X509EnhancedKeyUsageExtension(asn, false);
                break;
            case X509CertificatePropertyType.RootProgramCertificatePolicies:
                UnderlyingType = typeof(X509CertificatePoliciesExtension);
                PropertyValue = new X509CertificatePoliciesExtension(bytes, false);
                break;
            case X509CertificatePropertyType.OcspResponse:
                UnderlyingType = typeof(OCSPResponse);
                PropertyValue = new OCSPResponse(bytes);
                break;
            case X509CertificatePropertyType.CrossCertificateDistributionPoints:
            case X509CertificatePropertyType.CTLNextUpdateLocation:
                UnderlyingType = typeof(X509AlternativeNameCollection);
                PropertyValue = new X509AlternativeNameCollection();
                ((X509AlternativeNameCollection)PropertyValue).Decode(bytes);
                ((X509AlternativeNameCollection)PropertyValue).Close();
                break;
        }
    }
    void initializeStruct(IntPtr ptr) {
        switch (PropertyName) {
            case X509CertificatePropertyType.Handle:
                UnderlyingType = typeof(IntPtr);
                PropertyValue = ptr;
                break;
            case X509CertificatePropertyType.KeyContext:
                UnderlyingType = typeof(CERT_KEY_CONTEXT);
                PropertyValue = Marshal.PtrToStructure(ptr, typeof(CERT_KEY_CONTEXT));
                break;
            case X509CertificatePropertyType.ProviderInfo:
                UnderlyingType = typeof(KeyProviderInfo);
                CRYPT_KEY_PROV_INFO provInfo = Marshal.PtrToStructure<CRYPT_KEY_PROV_INFO>(ptr);
                PropertyValue = new KeyProviderInfo(provInfo);
                break;
        }
    }
    void initializeStruct(Byte[] bytes) {
        switch (PropertyName) {
            case X509CertificatePropertyType.CEPEnrollmentInfo:
                UnderlyingType = typeof(X509CEPEnrollmentPropertyInfo);
                PropertyValue = new X509CEPEnrollmentPropertyInfo(bytes);
                break;
            case X509CertificatePropertyType.EnrollmentInfo:
                UnderlyingType = typeof(X509EnrollmentPropertyInfo);
                PropertyValue = new X509EnrollmentPropertyInfo(bytes);
                break;
        }
    }
}