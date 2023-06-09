using System.Collections.Generic;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a collection of <see cref="X509CRL2"/> objects.
/// </summary>
public class X509CRL2Collection : BasicCollection<X509CRL2> {
    /// <summary>
    /// Initializes a new instance of the <see cref="X509CRL2Collection"/> class without any <see cref="X509CRL2"/> information.
    /// </summary>
    public X509CRL2Collection() { }
    /// <summary>
    /// Initializes a new instance of the <see cref="X509CRL2Collection"/> class from an array of <see cref="X509CRL2"/> objects.
    /// </summary>
    /// <param name="revocationLists">An array of <see cref="X509CRL2"/> objects.</param>
    public X509CRL2Collection(IEnumerable<X509CRL2> revocationLists) : base(revocationLists) { }
}