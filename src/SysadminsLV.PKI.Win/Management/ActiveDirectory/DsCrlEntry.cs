using System;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents a certificate object in Active Directory.
    /// </summary>
    public class DsCrlEntry {
        internal DsCrlEntry(String hostName, String name, X509CRL2 crl) {
            HostName = hostName;
            IssuerName = name;
            CRL = crl;
        }

        /// <summary>
        /// Gets the certification autority's host name associated with the current CRL object.
        /// </summary>
        public String HostName { get; }
        /// <summary>
        /// Gets the Active Directory entry name that holds current certificate object.
        /// </summary>
        public String IssuerName { get; }
        /// <summary>
        /// Gets the CRL type.
        /// </summary>
        public X509CrlType CrlType => CRL.Type;
        /// <summary>
        /// Gets the certificate associated with the current Active Directory entry.
        /// </summary>
        public X509CRL2 CRL { get; }

        /// <inheritdoc />
        public override Boolean Equals(Object other) {
            return !(other is null)
                   && (ReferenceEquals(this, other)
                       || other.GetType() == GetType()
                       && Equals((DsCrlEntry) other));
        }
        /// <summary>
        /// Determines whether the specified object is equal to the current object. Two CRL entries are equal when
        /// all public members of this object are same.
        /// </summary>
        /// <inheritdoc cref="Equals(Object)" select="param|returns"/>
        /// <returns></returns>
        protected Boolean Equals(DsCrlEntry other) {
            return String.Equals(HostName, other.HostName, StringComparison.OrdinalIgnoreCase)
                   && String.Equals(IssuerName, other.IssuerName, StringComparison.OrdinalIgnoreCase)
                   && CRL.Type == other.CRL.Type;
        }
        /// <inheritdoc />
        public override Int32 GetHashCode() {
            unchecked {
                Int32 hashCode = StringComparer.OrdinalIgnoreCase.GetHashCode(HostName);
                hashCode = (hashCode * 397) ^ StringComparer.OrdinalIgnoreCase.GetHashCode(IssuerName);
                hashCode = (hashCode * 397) ^ CRL.Type.GetHashCode();
                return hashCode;
            }
        }
    }
}