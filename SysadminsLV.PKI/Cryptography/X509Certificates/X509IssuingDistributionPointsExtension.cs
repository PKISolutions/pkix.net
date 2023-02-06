using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Cryptography.X509Certificates; 

public sealed class X509IssuingDistributionPointsExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.IssuingDistributionPoint);

    /// <summary>
    /// Initializes a new instance of the <see cref="X509IssuingDistributionPointsExtension"/> class using an
    /// <see cref="System.Security.Cryptography.AsnEncodedData"/> object and a value that identifies whether the extension is critical.
    /// </summary>
    /// <param name="issuingDistributionPoints">The encoded data to use to create the extension.</param>
    /// <param name="critical">
    ///		<strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
    /// </param>
    /// <exception cref="System.ArgumentException">
    ///		The data in the <strong>distributionPoints</strong> parameter is not valid extension value.
    /// </exception>
    public X509IssuingDistributionPointsExtension(AsnEncodedData issuingDistributionPoints, Boolean critical)
        : base(_oid, issuingDistributionPoints.RawData, critical) {
        decode();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509IssuingDistributionPointsExtension"/> class using an
    /// distribution point and partitioned CRL configuration.
    /// </summary>
    /// <param name="distributionPoint">Specifies an instance of <see cref="SysadminsLV.PKI.Cryptography.X509Certificates.X509DistributionPoint"/> that contains CRL location.</param>
    /// <param name="indirect">Specifies whether the CRL is indirect CRL.</param>
    /// <param name="reasons">Specifies whether the CRL is partitioned by a subset of revocation reasons.</param>
    /// <param name="scope">Specifies the scope for CRL.</param>
    /// <exception cref="System.ArgumentNullException"><strong>distributionPoint</strong> parameter is NULL.</exception>
    public X509IssuingDistributionPointsExtension(
        X509DistributionPoint distributionPoint,
        Boolean indirect = false,
        X509RevocationReasonFlag reasons = X509RevocationReasonFlag.None,
        IssuingDistributionPointScope scope = IssuingDistributionPointScope.None) {
        if (distributionPoint == null) {
            throw new ArgumentNullException(nameof(distributionPoint));
        }

        encode(distributionPoint, indirect, reasons, scope);
    }

    /// <summary>
    /// Gets the CRL distribution point for this CRL scope. This property can be NULL.
    /// </summary>
    public X509DistributionPoint DistributionPoint { get; private set; }
    /// <summary>
    /// Gets a status if CRL scope contains only end entity certificates.
    /// </summary>
    public Boolean OnlyUserCerts { get; private set; }
    /// <summary>
    /// Gets a status if CRL scope contains only CA certificates.
    /// </summary>
    public Boolean OnlyCaCerts { get; private set; }
    /// <summary>
    /// Gets a status if CRL scope contains only Attribute certificates.
    /// </summary>
    public Boolean OnlyAttributeCerts { get; private set; }
    /// <summary>
    /// Gets a status if CRL is partitioned by a subset of revocation reasons.
    /// </summary>
    public X509RevocationReasonFlag Reasons { get; private set; }
    /// <summary>
    /// Gets a status if current CRL is indirect CRL.
    /// </summary>
    public Boolean IndirectCRL { get; private set; }

    void encode(X509DistributionPoint distributionPoint, Boolean indirect, X509RevocationReasonFlag reasons, IssuingDistributionPointScope scope) {
        Oid = _oid;
        Critical = true;

        var builder = Asn1Builder.Create();
        if (distributionPoint != null) {
            DistributionPoint = distributionPoint;
            builder.AddExplicit(0, distributionPoint.RawData, true);
        }
        switch (scope) {
            case IssuingDistributionPointScope.OnlyUserCerts:
                OnlyUserCerts = true;
                builder.AddImplicit(1, new Asn1Boolean(true).RawData, false);
                break;
            case IssuingDistributionPointScope.OnlyCaCerts:
                OnlyCaCerts = true;
                builder.AddImplicit(2, new Asn1Boolean(true).RawData, false);
                break;
        }
        if (reasons != X509RevocationReasonFlag.None) {
            Reasons = reasons;
            // do encoding trick since encoding matches the Key Usage extension encoding
            builder.AddExplicit(3, x => x.AddDerData(new X509KeyUsageExtension((X509KeyUsageFlags)reasons, false).RawData));
        }
        if (indirect) {
            IndirectCRL = true;
            builder.AddImplicit(4, new Asn1Boolean(true).RawData, false);
        }
        if (scope == IssuingDistributionPointScope.OnlyAttributeCerts) {
            OnlyAttributeCerts = true;
            builder.AddImplicit(5, new Asn1Boolean(true).RawData, false);
        }

        RawData = builder.GetEncoded();
    }

    void decode() {
        var asn = new Asn1Reader(RawData);
        if (asn.PayloadLength == 0) {
            return;
        }

        asn.MoveNext();
        do {
            switch (asn.Tag) {
                case 0xa0:
                    DistributionPoint = new X509DistributionPoint(Asn1Utils.Encode(asn.GetTagRawData(), 48));
                    break;
                case 0xa1:
                    OnlyUserCerts = Asn1Utils.DecodeBoolean(asn.GetPayload());
                    break;
                case 0xa2:
                    OnlyCaCerts = Asn1Utils.DecodeBoolean(asn.GetPayload());
                    break;
                case 0xa3:
                    var val = new Asn1BitString(asn.GetPayload());
                    if (val.Value.Length > 1) {
                        Reasons = (X509RevocationReasonFlag) BitConverter.ToUInt16(val.Value, 0);
                    } else if (val.Value.Length == 1) {
                        Reasons = (X509RevocationReasonFlag) val.Value[0];
                    }
                    break;
                case 0xa4:
                    IndirectCRL = Asn1Utils.DecodeBoolean(asn.GetPayload());
                    break;
                case 0xa5:
                    OnlyAttributeCerts = Asn1Utils.DecodeBoolean(asn.GetPayload());
                    break;
            }
        } while (asn.MoveNextSibling());
    }
}
/*
IssuingDistributionPoint::= SEQUENCE {
    distributionPoint          [0] DistributionPointName OPTIONAL,
    onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
    onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
    onlySomeReasons            [3] ReasonFlags OPTIONAL,
    indirectCRL                [4] BOOLEAN DEFAULT FALSE,
    onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
*/