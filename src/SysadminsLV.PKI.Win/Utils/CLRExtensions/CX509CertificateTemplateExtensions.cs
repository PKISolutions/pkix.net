using System;
using Interop.CERTENROLLLib;

namespace SysadminsLV.PKI.Utils.CLRExtensions;
static class CX509CertificateTemplateExtensions {
    public static Int32 GetInt32(this IX509CertificateTemplate template, EnrollmentTemplateProperty propertyName) {
        try {
            return Convert.ToInt32(template.Property[propertyName]);
        } catch {
            return default;
        }
    }
    public static TEnum GetEnum<TEnum>(this IX509CertificateTemplate template, EnrollmentTemplateProperty propertyName) where TEnum : struct, Enum {
        try {
            return (TEnum)Enum.Parse(typeof(TEnum), Convert.ToInt32(template.Property[propertyName]).ToString());
        } catch {
            return default;
        }
    }
    public static Int64 GetInt64(this IX509CertificateTemplate template, EnrollmentTemplateProperty propertyName) {
        try {
            return Convert.ToInt64(template.Property[propertyName]);
        } catch {
            return default;
        }
    }
    public static TValue[] GetCollectionValue<TValue>(this IX509CertificateTemplate template, EnrollmentTemplateProperty propertyName) {
        try {
            return (TValue[])template.Property[propertyName];
        } catch {
            return Array.Empty<TValue>();
        }
    }
}
