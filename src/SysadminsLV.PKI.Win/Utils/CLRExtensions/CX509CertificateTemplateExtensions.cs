using System;
using Interop.CERTENROLLLib;

namespace SysadminsLV.PKI.Utils.CLRExtensions;

/// <summary>
/// Contains extension methods for <strong>IX509CertificateTemplate</strong> COM interface.
/// </summary>
static class CX509CertificateTemplateExtensions {
    /// <summary>
    /// Gets signed 32-bit integer from OLE object.
    /// </summary>
    /// <param name="template">Current template instance.</param>
    /// <param name="propertyName">Property to retrieve.</param>
    /// <param name="defaultValue">Optional default value to return if requested property doesn't exist or is empty.</param>
    /// <returns>Signed 32-bit integer.</returns>
    public static Int32 GetInt32(this IX509CertificateTemplate template, EnrollmentTemplateProperty propertyName, Int32 defaultValue = default) {
        try {
            return Convert.ToInt32(template.Property[propertyName]);
        } catch {
            return defaultValue;
        }
    }
    /// <summary>
    /// Gets signed 64-bit integer from OLE object.
    /// </summary>
    /// <param name="template">Current template instance.</param>
    /// <param name="propertyName">Property to retrieve.</param>
    /// <param name="defaultValue">Optional default value to return if requested property doesn't exist or is empty.</param>
    /// <returns>Signed 64-bit integer.</returns>
    public static Int64 GetInt64(this IX509CertificateTemplate template, EnrollmentTemplateProperty propertyName, Int64 defaultValue = default) {
        try {
            return Convert.ToInt64(template.Property[propertyName]);
        } catch {
            return defaultValue;
        }
    }
    /// <summary>
    /// Gets scalar value from OLE object.
    /// </summary>
    /// <param name="template">Current template instance.</param>
    /// <param name="propertyName">Property to retrieve.</param>
    /// <param name="defaultValue">Optional default value to return if requested property doesn't exist or is empty.</param>
    /// <returns>Scalar value.</returns>
    public static TValue GetScalarValue<TValue>(this IX509CertificateTemplate template, EnrollmentTemplateProperty propertyName, TValue defaultValue = default) {
        try {
            return (TValue)template.Property[propertyName];
        } catch {
            return defaultValue;
        }
    }
    /// <summary>
    /// Gets enum value from 32-bit signed integer from OLE object.
    /// </summary>
    /// <param name="template">Current template instance.</param>
    /// <param name="propertyName">Property to retrieve.</param>
    /// <param name="defaultValue">Optional default value to return if requested property doesn't exist or is empty.</param>
    /// <returns>Enum value.</returns>
    public static TEnum GetEnum<TEnum>(this IX509CertificateTemplate template, EnrollmentTemplateProperty propertyName, TEnum defaultValue = default) where TEnum : struct, Enum {
        try {
            return (TEnum)Enum.Parse(typeof(TEnum), Convert.ToInt32(template.Property[propertyName]).ToString());
        } catch {
            return defaultValue;
        }
    }
    /// <summary>
    /// Gets a collection of scalar values from OLE object.
    /// </summary>
    /// <param name="template">Current template instance.</param>
    /// <param name="propertyName">Property to retrieve.</param>
    /// <returns>Scalar array.</returns>
    public static TValue[] GetCollectionValue<TValue>(this IX509CertificateTemplate template, EnrollmentTemplateProperty propertyName) {
        try {
            return (TValue[])template.Property[propertyName];
        } catch {
            return [];
        }
    }
}
