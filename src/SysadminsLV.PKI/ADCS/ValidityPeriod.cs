using System;
using System.Runtime.InteropServices.ComTypes;

namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Represents Active Directory Certificate Services (AD CS) time span periods that often represent validity periods.
/// </summary>
public class ValidityPeriod {
    ValidityPeriod(Int64 fileTime) {
        Validity = TimeSpan.FromTicks(fileTime < 0 ? fileTime * -1 : fileTime);
        ValidityString = readValidity(fileTime);
    }

    /// <summary>
    /// Gets the validity as time span.
    /// </summary>
    public TimeSpan Validity { get; }
    /// <summary>
    /// Gets textual representation of time span.
    /// </summary>
    public String ValidityString { get; }
    
    static String readValidity(Int64 fileTime = 0) {
        Int64 totalHours = (Int64)(fileTime * -.0000001 / 3600);
        if (totalHours % 8760 == 0 && totalHours / 8760 >= 1) {
            return Convert.ToString(totalHours / 8760) + " years";
        }

        if (totalHours % 720 == 0 && totalHours / 720 >= 1) {
            return Convert.ToString(totalHours / 720) + " months";
        }

        if (totalHours % 168 == 0 && totalHours / 168 >= 1) {
            return Convert.ToString(totalHours / 168) + " weeks";
        }

        if (totalHours % 24 == 0 && totalHours / 24 >= 1) {
            return Convert.ToString(totalHours / 24) + " days";
        }

        if (totalHours % 1 == 0 && totalHours / 1 >= 1) {
            return Convert.ToString(totalHours) + " hours";
        }

        return "0 hours";
    }

    /// <summary>
    /// Creates an instance of <see cref="ValidityPeriod"/> from COM file time.
    /// </summary>
    /// <param name="fileTime">COM file time.</param>
    /// <returns>An instance of <see cref="ValidityPeriod"/>.</returns>
    public static ValidityPeriod FromFileTime(FILETIME fileTime) {
        Int64 longTime = ((Int64)fileTime.dwHighDateTime << 32) | (UInt32)fileTime.dwLowDateTime;
        return new ValidityPeriod(longTime);
    }
    /// <summary>
    /// Creates an instance of <see cref="ValidityPeriod"/> from binary file time.
    /// </summary>
    /// <param name="fileTime">COM file time in binary form. Must be exactly 8 bytes.</param>
    /// <returns>An instance of <see cref="ValidityPeriod"/>.</returns>
    /// <exception cref="ArgumentNullException">
    ///     <strong>fileTime</strong> parameter is null.
    /// </exception>
    public static ValidityPeriod FromFileTime(Byte[] fileTime) {
        if (fileTime == null) {
            throw new ArgumentNullException(nameof(fileTime));
        }
        Int64 longTime = BitConverter.ToInt64(fileTime, 0);
        return new ValidityPeriod(longTime);
    }
    /// <summary>
    /// Creates an instance of <see cref="ValidityPeriod"/> from long file time.
    /// </summary>
    /// <param name="fileTime">Number of ticks.</param>
    /// <returns>An instance of <see cref="ValidityPeriod"/>.</returns>
    public static ValidityPeriod FromFileTime(Int64 fileTime) {
        return new ValidityPeriod(fileTime);
    }
    /// <summary>
    /// Creates an instance of <see cref="ValidityPeriod"/> from timespan.
    /// </summary>
    /// <param name="timeSpan">Time span.</param>
    /// <returns>An instance of <see cref="ValidityPeriod"/>.</returns>
    public static ValidityPeriod FromTimeSpan(TimeSpan timeSpan) {
        return new ValidityPeriod(timeSpan.Ticks);
    }
}
