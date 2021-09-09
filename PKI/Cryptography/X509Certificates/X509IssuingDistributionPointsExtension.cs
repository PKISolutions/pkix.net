using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates {
    public class X509IssuingDistributionPointsExtension : X509Extension {
        readonly Oid _oid = new Oid(X509ExtensionOid.IssuingDistributionPoint);

        /// <summary>
        /// Initializes a new instance of the <see cref="X509IssuingDistributionPointsExtension"/> class using an
        /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="issuingDistributionPoints">The encoded data to use to create the extension.</param>
        /// <param name="critical">
        ///		<strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
        /// </param>
        /// <exception cref="ArgumentException">
        ///		The data in the <strong>distributionPoints</strong> parameter is not valid extension value.
        /// </exception>
        public X509IssuingDistributionPointsExtension(AsnEncodedData issuingDistributionPoints, Boolean critical)
            : base(X509ExtensionOid.IssuingDistributionPoint, issuingDistributionPoints.RawData, critical) {
            decode();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="distributionPoint"></param>
        /// <param name="onlySomeReason">Specifies whether the CRL is partitioned by a subset of revocation reasons.</param>
        /// <param name="indirect">Specifies whether the CRL is indirect CRL.</param>
        /// <param name="scope">Specifies the scope for CRL.</param>
        public X509IssuingDistributionPointsExtension(X509DistributionPoint distributionPoint, Boolean onlySomeReason, Boolean indirect, IssuingDistributionPointScope scope) {
            encode(distributionPoint, onlySomeReason, indirect, scope);
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
        public Boolean OnlySomeReasons { get; private set; }
        /// <summary>
        /// Gets a status if current CRL is indirect CRL.
        /// </summary>
        public Boolean IndirectCRL { get; private set; }

        void encode(X509DistributionPoint distributionPoint, Boolean onlySomeReason, Boolean indirect, IssuingDistributionPointScope scope) {
            Oid = _oid;
            Critical = true;

            var builder = Asn1Builder.Create();
            if (distributionPoint != null) {
                DistributionPoint = distributionPoint;
                builder.AddDerData(new Asn1Reader(distributionPoint.RawData).GetPayload());
            }
            if (scope == IssuingDistributionPointScope.OnlyUserCerts) {
                OnlyUserCerts = true;
                builder.AddExplicit(1, x => x.AddBoolean(true));
            } else if (scope == IssuingDistributionPointScope.OnlyCaCerts) {
                OnlyCaCerts = true;
                builder.AddExplicit(2, x => x.AddBoolean(true));
            }
            if (onlySomeReason) {
                OnlySomeReasons = true;
                builder.AddExplicit(3, x => x.AddBoolean(true));
            }
            if (indirect) {
                IndirectCRL = true;
                builder.AddExplicit(4, x => x.AddBoolean(true));
            }
            if (scope == IssuingDistributionPointScope.OnlyAttributeCerts) {
                OnlyAttributeCerts = true;
                builder.AddExplicit(5, x => x.AddBoolean(true));
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
                        OnlySomeReasons = Asn1Utils.DecodeBoolean(asn.GetPayload());
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
}
/*
IssuingDistributionPoint::= SEQUENCE {
    distributionPoint          [0]     DistributionPointName OPTIONAL,
    onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
    onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
    onlySomeReasons            [3] ReasonFlags OPTIONAL,
    indirectCRL                [4] BOOLEAN DEFAULT FALSE,
    onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
*/