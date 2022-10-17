using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a Microsoft proprietary Security Identifier (SID) extension.
/// <see href="https://support.microsoft.com/kb/5014754">KB5014754</see> for more information.
/// </summary>
public sealed class X509NtdsSecurityExtension : X509Extension {
    static readonly Oid _oid = new Oid(X509ExtensionOid.NtdsSecurityExtension, "NTDS Security");

    /// <summary>
    ///     Initializes a new instance of the <strong>X509NtdsSecurityExtension</strong> class from
    ///     security identifier (SID) and value that determines if the extension is critical.
    /// </summary>
    /// <param name="sid">
    ///     An instance that represents a security identifier.
    /// </param>
    /// <param name="critical">
    ///     <strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
    /// </param>
    /// <exception cref="ArgumentException">
    ///     <strong>sid</strong> parameter represents empty security identifier.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    ///     <string>sid</string> parameter is null.
    /// </exception>
    public X509NtdsSecurityExtension(SecurityIdentifier sid, Boolean critical) {
        if (sid == null) {
            throw new ArgumentNullException(nameof(sid));
        }
        if (String.IsNullOrEmpty(sid.Value)) {
            throw new ArgumentException("The security identifier (SID) value cannot be empty.");
        }
        initialize(sid);
        Oid = _oid;
        Critical = critical;
    }
    /// <param name="extensionValue">The encoded data to use to create the extension.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    public X509NtdsSecurityExtension(AsnEncodedData extensionValue, Boolean critical)
        : base(_oid, extensionValue.RawData, critical) {
        decode(extensionValue.RawData);
    }

    /// <summary>
    /// Gets the security identifier (SID) string associated with this extension.
    /// </summary>
    public String SecurityIdentifier { get; private set; }

    void initialize(IdentityReference sid) {
        SecurityIdentifier = sid.Value;
        Byte[] sidBytes = Encoding.ASCII.GetBytes(SecurityIdentifier);
        RawData = Asn1Builder.Create()
            .AddExplicit(0, x => {
                                x.AddObjectIdentifier(new Oid("1.3.6.1.4.1.311.25.2.1"));
                                return x.AddExplicit(0, y => y.AddOctetString(sidBytes));
                            }).GetEncoded();
    }
    void decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        asn.MoveNextAndExpectTags(0xa0);
        asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
        asn.MoveNextAndExpectTags(0xa0);
        asn.MoveNextAndExpectTags((Byte)Asn1Type.OCTET_STRING);

        SecurityIdentifier = Encoding.ASCII.GetString(asn.GetPayload());
    }

    /// <summary>
    /// Returns a formatted version of the Abstract Syntax Notation One (ASN.1)-encoded data as a string.
    /// </summary>
    /// <param name="multiLine"><strong>True</strong> if the return string should contain carriage returns; otherwise, <strong>False</strong>.</param>
    /// <returns>A formatted string that represents the Abstract Syntax Notation One (ASN.1)-encoded data.</returns>
    public override String Format(Boolean multiLine) {
        var SB = new StringBuilder();
        SB.Append("SID: " + SecurityIdentifier);
        if (multiLine) { SB.Append(Environment.NewLine); }
        return SB.ToString();
    }
}