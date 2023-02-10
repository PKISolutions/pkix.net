using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Utils.CLRExtensions;

/// <summary>
/// Contains extension methods for <see cref="X509Extension"/> class.
/// </summary>
public static class X509ExtensionExtensions {
    /// <summary>
    /// Converts default instance of <see cref="X509Extension"/> class to a specific extension implementation object.
    /// </summary>
    /// <param name="extension">Default instance of <see cref="X509Extension"/> class.</param>
    /// <returns>Explicit extension implementation if defined, otherwise, the same object is returned.</returns>
    public static X509Extension ConvertExtension(this X509Extension extension) {
        AsnEncodedData asnData = new AsnEncodedData(extension.Oid, extension.RawData);
        switch (extension.Oid.Value) {
            case X509ExtensionOid.CAVersion:
                return new X509CAVersionExtension(asnData, extension.Critical);
            case X509ExtensionOid.NextCRLPublish:
                return new X509NextCRLPublishExtension(asnData, extension.Critical);
            case X509ExtensionOid.CertTemplateInfoV2:
                return new X509CertificateTemplateExtension(asnData, extension.Critical);
            case X509ExtensionOid.ApplicationPolicies:
                return new X509ApplicationPoliciesExtension(asnData, extension.Critical);
            case X509ExtensionOid.ApplicationPolicyMappings:
                return new X509ApplicationPolicyMappingsExtension(asnData);
            case X509ExtensionOid.ApplicationPolicyConstraints:
                return new X509ApplicationPolicyConstraintsExtension(asnData);
            case X509ExtensionOid.PublishedCrlLocations:
                return new X509PublishedCrlLocationsExtension(asnData, extension.Critical);
            case X509ExtensionOid.NtdsSecurityExtension:
                return new X509NtdsSecurityExtension(asnData, extension.Critical);
            case X509ExtensionOid.AuthorityInformationAccess:
                return new X509AuthorityInformationAccessExtension(asnData, extension.Critical);
            case X509ExtensionOid.OcspNonce:
                return new X509NonceExtension(asnData, extension.Critical);
            case X509ExtensionOid.OcspCRLReference:
                return new X509CRLReferenceExtension(asnData, extension.Critical);
            case X509ExtensionOid.ArchiveCutoff:
                return new X509ArchiveCutoffExtension(asnData, extension.Critical);
            case X509ExtensionOid.ServiceLocator:
                return new X509ServiceLocatorExtension(asnData, extension.Critical);
            case X509ExtensionOid.SubjectKeyIdentifier:
                return new X509SubjectKeyIdentifierExtension(asnData, extension.Critical);
            case X509ExtensionOid.KeyUsage:
                return new X509KeyUsageExtension(asnData, extension.Critical);
            case X509ExtensionOid.SubjectAlternativeNames:
                return new X509SubjectAlternativeNamesExtension(asnData, extension.Critical);
            case X509ExtensionOid.IssuerAlternativeNames:
                return new X509IssuerAlternativeNamesExtension(asnData, extension.Critical);
            case X509ExtensionOid.BasicConstraints:
                return new X509BasicConstraintsExtension(asnData, extension.Critical);
            case X509ExtensionOid.CRLNumber:
                return new X509CRLNumberExtension(asnData, extension.Critical);
            case X509ExtensionOid.IssuingDistributionPoint:
                return new X509IssuingDistributionPointsExtension(asnData, extension.Critical);
            case X509ExtensionOid.NameConstraints:
                return new X509NameConstraintsExtension(asnData);
            case X509ExtensionOid.CRLDistributionPoints:
                return new X509CRLDistributionPointsExtension(asnData, extension.Critical);
            case X509ExtensionOid.CertificatePolicies:
                return new X509CertificatePoliciesExtension(asnData, extension.Critical);
            case X509ExtensionOid.CertificatePolicyMappings:
                return new X509CertificatePolicyMappingsExtension(asnData);
            case X509ExtensionOid.AuthorityKeyIdentifier:
                return new X509AuthorityKeyIdentifierExtension(asnData, extension.Critical);
            case X509ExtensionOid.CertificatePolicyConstraints:
                return new X509CertificatePolicyConstraintsExtension(asnData);
            case X509ExtensionOid.EnhancedKeyUsage:
                return new X509EnhancedKeyUsageExtension(asnData, extension.Critical);
            case X509ExtensionOid.FreshestCRL:
                return new X509FreshestCRLExtension(asnData, extension.Critical);
            default:
                return extension;
        }
    }
    /// <summary>
    /// Encodes current extension to ASN.1-encoded byte array.
    /// </summary>
    /// <param name="extension">Extension to encode.</param>
    /// <exception cref="ArgumentNullException"><strong>extension</strong> parameter is null.</exception>
    /// <exception cref="ArgumentException">Extension object is not properly initialized.</exception>
    /// <returns></returns>
    public static Byte[] Encode(this X509Extension extension) {
        if (extension == null) {
            throw new ArgumentNullException(nameof(extension));
        }
        if (String.IsNullOrEmpty(extension.Oid.Value)) {
            throw new ArgumentException();
        }
        var rawData = new List<Byte>(Asn1Utils.EncodeObjectIdentifier(extension.Oid));
        if (extension.Critical) {
            rawData.AddRange(Asn1Utils.EncodeBoolean(true));
        }

        rawData.AddRange(Asn1Utils.Encode(extension.RawData, (Byte)Asn1Type.OCTET_STRING));
        return Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    /// <summary>
    /// Decodes ASN.1-encoded byte array to an instance of <see cref="X509Extension"/> class.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array that represents full extension information.</param>
    /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null.</exception>
    /// <exception cref="Asn1InvalidTagException">Decoder encountered an unexpected ASN.1 type identifier.</exception>
    /// <returns>Decoded extension object.</returns>
    public static X509Extension Decode(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }

        return Decode(new Asn1Reader(rawData));
    }
    /// <summary>
    /// Decodes ASN.1-encoded byte array to an instance of <see cref="X509Extension"/> class.
    /// </summary>
    /// <param name="asn">ASN.1 reader that points to the beginning of the X.509 extension structure.</param>
    /// <exception cref="ArgumentNullException"><strong>asn</strong> parameter is null.</exception>
    /// <exception cref="Asn1InvalidTagException">Decoder encountered an unexpected ASN.1 type identifier.</exception>
    /// <returns>Decoded extension object.</returns>
    public static X509Extension Decode(Asn1Reader asn) {
        if (asn.Tag != 48) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        Int32 offset = asn.Offset;
        asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
        Oid oid = new Asn1ObjectIdentifier(asn).Value;
        Boolean critical = false;
        asn.MoveNextAndExpectTags((Byte)Asn1Type.BOOLEAN, (Byte)Asn1Type.OCTET_STRING);
        if (asn.Tag == (Byte)Asn1Type.BOOLEAN) {
            critical = Asn1Utils.DecodeBoolean(asn.GetTagRawData());
            asn.MoveNextAndExpectTags((Byte)Asn1Type.OCTET_STRING);
        }
        // at this point ASN points to OCTET_STRING

        X509Extension retValue = new X509Extension(oid, asn.GetPayload(), critical).ConvertExtension();
        asn.Seek(offset);
        return retValue;
    }
}