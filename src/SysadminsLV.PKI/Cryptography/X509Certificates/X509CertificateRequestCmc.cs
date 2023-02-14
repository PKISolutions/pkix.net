using System;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.Pkcs;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// The <strong>X509CertificateRequestCmc</strong> class represents a CMC (Certificate Management Message over CMS)
/// certificate request. A CMC request is always wrapped by a PKCS #7 certificate message syntax (CMS) object.
/// </summary>
/// <remarks>Currently, this class do not support extra CMC attributes.</remarks>
public sealed class X509CertificateRequestCmc : SignedPkcs7<X509CertificateRequestPkcs10> {
    /*
    CmcData ::= SEQUENCE 
    {
       controlSequence         ControlSequence,
       reqSequence             ReqSequence,
       cmsSequence             CmsSequence,
       otherMsgSequence        OtherMsgSequence
    }


    ControlSequence  ::=    SEQUENCE OF TaggedAttribute
    ReqSequence      ::=    SEQUENCE OF TaggedRequest
    CmsSequence      ::=    SEQUENCE OF TaggedContentInfo
    OtherMsgSequence ::=    SEQUENCE OF TaggedOtherMsg

    TaggedAttribute ::= SEQUENCE {
       bodyPartID              BodyPartID,
       type                    EncodedObjectID,
       values                  AttributeSetValue
    }

    TaggedRequest ::= CHOICE {
       tcr                     [0] IMPLICIT TaggedCertificationRequest
    }

    TaggedContentInfo ::= SEQUENCE {
       bodyPartID              BodyPartID,
       contentInfo             ANY
    }

    BodyPartID ::= INTEGER (0..4294967295)
    EncodedObjectID ::= OBJECT IDENTIFIER
    AttributeSetValue ::= SET OF ANY
     */
    /// <summary>
    /// Initializes a new instance of <strong>X509CertificateRequestCmc</strong> class from ASN.1-encoded
    /// byte array that represents encoded Certificate Management over CMS (CMC) object.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array that represents CMC object.</param>
    /// <remarks>
    /// Certificate Management over CMS (CMC) format and transport mechanism are defined in:
    /// <see href="https://tools.ietf.org/html/rfc5272">RFC 5272</see>,
    /// <see href="https://tools.ietf.org/html/rfc5273">RFC 5273</see>,
    /// <see href="https://tools.ietf.org/html/rfc5274">RFC 5274</see> and updated by
    /// <see href="https://tools.ietf.org/html/rfc6402">RFC 6402</see>.
    /// </remarks>
    public X509CertificateRequestCmc(Byte[] rawData) : base(rawData) { }

    /// <summary>
    /// Decodes embedded payload of the CMC message. Current implementation supports only PKCS#10 certificate
    /// request objects.
    /// </summary>
    /// <inheritdoc select="param"/>
    /// <remarks>This member cannot be inherited or overriden.</remarks>
    protected override void DecodeContent(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        asn.MoveNextAndExpectTags(0x30);             // ControlSequence  ::=    SEQUENCE OF TaggedAttribute
        asn.MoveNextSiblingAndExpectTags(0x30); // ReqSequence      ::=    SEQUENCE OF TaggedRequest
        asn.MoveNextAndExpectTags(0xa0);
        asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
        asn.MoveNextAndExpectTags(0x30);
        // theoretically, it is a sequence, but we pick only first request. Never seen an array of requests
        Content = new X509CertificateRequestPkcs10(asn.GetTagRawData());
    }
}