using System;
using System.Linq;
using System.Numerics;
using System.Text;

namespace SysadminsLV.PKI.CLRExtensions {
    /// <summary>
    /// Contains CLR extensions for <see cref="BigInteger"/> class.
    /// </summary>
    public static class BigIntegerExtensions {
        /// <summary>
        /// Gets a byte array of the current instance of <see cref="BigInteger"/> object in a little-endian byte order.
        /// </summary>
        /// <param name="bigInteger">Current <see cref="BigInteger"/> object.</param>
        /// <returns></returns>
        public static Byte[] ToLittleEndianByteArray(this BigInteger bigInteger) {
            return bigInteger.ToByteArray().Reverse().ToArray();
        }
        /// <summary>
        /// Initializes a <see cref="BigInteger"/> object from a binary bit string.
        /// </summary>
        /// <param name="bigInteger">Current <see cref="BigInteger"/> object.</param>
        /// <param name="bitString">Binary bit string.</param>
        internal static void FromBitString(this BigInteger bigInteger, String bitString) {
            BigInteger res = 0;
            foreach (Char c in bitString) {
                if (c != '0' && c != '1') { throw new ArgumentException("The bit string is invalid."); }
                res <<= 1;
                res += c == '1' ? 1 : 0;
            }
            bigInteger = res;
        }
        /// <summary>
        /// Converts current value of the <see cref="BigInteger"/> class to a binary string.
        /// </summary>
        /// <param name="bigint">Current <see cref="BigInteger"/> object.</param>
        /// <returns>Binary string.</returns>
        public static String ToBinaryString(this BigInteger bigint) {
            Byte[] bytes = bigint.ToByteArray();
            Int32 idx = bytes.Length - 1;

            // Create a StringBuilder having appropriate capacity.
            var base2 = new StringBuilder(bytes.Length * 8);

            // Convert first byte to binary.
            String binary = Convert.ToString(bytes[idx], 2);

            // Ensure leading zero exists if value is positive.
            if (binary[0] != '0' && bigint.Sign == 1) {
                base2.Append('0');
            }

            // Append binary string to StringBuilder.
            base2.Append(binary);

            // Convert remaining bytes adding leading zeros.
            for (idx--; idx >= 0; idx--) {
                base2.Append(Convert.ToString(bytes[idx], 2).PadLeft(8, '0'));
            }

            return base2.ToString();
        }
        /// <summary>
        /// Returns the number of '1' or '0' bits in the current <see cref="BigInteger"/> object.
        /// </summary>
        /// <param name="bigInteger">Current <see cref="BigInteger"/> object.</param>
        /// <param name="ones">
        /// <strong>True</strong> if the count of '1' should be calculated. <strong>False</strong> if the count of
        /// '0' should be calculated.
        /// </param>
        /// <returns>A number of '1' or '0' bits.</returns>
        public static BigInteger GetEnabledBitCount(this BigInteger bigInteger, Boolean ones = true) {
            BigInteger count = 0;
            BigInteger internalValue = bigInteger;
            while (internalValue > 0) {
                count += internalValue & 1;
                internalValue >>= 1;
            }
            return count;
        }
    }
}
