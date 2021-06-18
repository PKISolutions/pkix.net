using PKI.Utils;
using SysadminsLV.PKI;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a collection of <see cref="X509CTLEntry"/> objects.
    /// </summary>
    [Obsolete("X509CTLEntryCollection is replaced with X509CertificateTrustListEntryCollection class.")]
    public class X509CTLEntryCollection : BasicCollection<X509CTLEntry> {

        /// <summary>
        /// Adds an <see cref="X509CTLEntry"/> object to the <see cref="X509CTLEntryCollection"/> object.
        /// </summary>
        /// <param name="entry">The <see cref="X509CTLEntry"/> object to add to the collection.</param>
        /// <exception cref="AccessViolationException">The collection is closed and is read-only.</exception>
        /// <returns>The index of the added <see cref="X509CTLEntry"/> object.</returns>
        /// <remarks>
        /// Use this method to add an <see cref="X509CTLEntry"/> object to an existing collection at the current location.
        /// <para>The method returns a '-1' value if the object is already in the collection.</para>
        /// </remarks>
        public override void Add(X509CTLEntry entry) {
            if (IsReadOnly) { throw new AccessViolationException(Error.E_COLLECTIONCLOSED); }
            if (InternalList.Contains(entry)) { return; }
            InternalList.Add(entry);
        }
        /// <summary>
        /// Closes current collection state and makes it read-only. The collection cannot be modified further.
        /// </summary>
        public void Close() { IsReadOnly = true; }

        /// <summary>
        /// Gets an <see cref="X509CTLEntry"/> object from the <see cref="X509CTLEntryCollection"/> object by certificate's
        /// Thumbprint value.
        /// </summary>
        /// <param name="thumbprint">A string that represents a <see cref="X509CTLEntry.Thumbprint">Thumbprint</see>
        /// property.</param>
        /// <remarks>Use this property to retrieve an <see cref="X509CTLEntry"/> object from an <see cref="X509CTLEntryCollection"/>
        /// object if you know the <see cref="X509CTLEntry.Thumbprint">Thumbprint</see> value of the <see cref="X509CTLEntry"/>
        /// object. You can use the <see cref="this[String]"/> property to retrieve an <see cref="X509CTLEntry"/> object if you know
        /// its location in the collection</remarks>
        /// <returns>An <see cref="X509CTLEntry"/> object.</returns>
        public X509CTLEntry this[String thumbprint] {
            get {
                foreach (X509CTLEntry entry in InternalList) {
                    if (entry.Thumbprint.ToLower() == thumbprint.ToLower()) { return entry; }
                }
                return null;
            }
        }
    }
}