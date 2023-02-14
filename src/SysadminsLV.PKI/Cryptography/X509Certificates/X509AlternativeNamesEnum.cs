namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Contains alternative name enumeration used by Subject Alternative Names extension.
/// </summary>
public enum X509AlternativeNamesEnum {
    /// <summary>
    /// The name type is not identified.
    /// </summary>
    Unknown           = 0,
    /// <summary>
    /// The name consists of an object identifier (OID) and a byte array that contains the name value.
    /// </summary>
    OtherName         = 1,
    /// <summary>
    /// The name is an email address such as <i>someone@example.com</i>.
    /// </summary>
    Rfc822Name        = 2,
    /// <summary>
    /// The name is a Domain Name System (DNS) name such as MyDomain.Company.com. The format of a DNS name
    /// is Host.Entity.Domain. For more information about DNS, see <see href="http://tools.ietf.org/html/rfc1034">RFC 1034</see>
    /// (Domain Names—Concepts and Facilities), and <see href="http://tools.ietf.org/html/rfc1035">RFC 1035</see>
    /// (Domain Names—Implementation and Specification).
    /// </summary>
    DnsName           = 3,
    /// <summary>
    /// The name is an X.500 directory name such as <i>CN=administrators,CN=users,DC=corp,DC=company,DC=com</i>.
    /// </summary>
    DirectoryName     = 5,
    /// <summary>
    /// The name is a URL such as <i>http://www.company.com/</i>.
    /// </summary>
    URL               = 7,
    /// <summary>
    /// The name is an Internet Protocol (IP) address in dotted decimal format <i>123.456.789.123</i>.
    /// </summary>
    IpAddress         = 8,
    /// <summary>
    /// The name is an object identifier (OID) registered with the International Standards Organization (ISO).
    /// </summary>
    RegisteredId      = 9,
    /// <summary>
    /// The name is a Directory Service Agent GUID. The GUID identifies a server to the Active Directory
    /// replication system as a domain controller.
    /// </summary>
    Guid              = 10,
    /// <summary>
    /// The name is a user principal name (UPN). A UPN is a user logon name in email address format. That is, a
    /// UPN consists of a shorthand name for a user account followed by the DNS name of the Active Directory
    /// tree in which the user object resides. It has the form UserName@DNS_suffix. An example is
    /// <i>UserName@Microsoft.com</i> where Microsoft.com is the DNS suffix and <i>UserName</i> is a placeholder
    /// for a shorthand name assigned by Microsoft to a user account.
    /// </summary>
    UserPrincipalName = 11
}