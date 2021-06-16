using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography.Pkcs;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography {
    /// <summary>
    /// Represents a <see href="https://tools.ietf.org/html/rfc3161">RFC 3161</see> implementation of Time-Stamp Protocol response.
    /// </summary>
    /// <remarks>
    ///     This class has full support of <see href="https://tools.ietf.org/html/rfc3161">RFC 3161</see> response format returned when
    ///     using <see cref="TspRfc3161Request"/> Time-Stamp request format. Using other time-Stamp requests, Time-Stamp  Authority (TSA)
    ///     may respond with other encapsulated data. In this case, only <see cref="Status"/>, <see cref="ResponseType"/>,
    ///     <see cref="GenerationTimestamp"/> and <see cref="RawData"/> properties are presented. Other properties have their default value
    ///     and <see cref="RequestMessage"/> is null.
    /// </remarks>
    public class TspResponse {
        const String TSP_OID = "1.3.6.1.5.5.7.3.8";
        const String SIGNING_TIME = "1.2.840.113549.1.9.5";
        readonly IList<X509Extension> _extensions = new List<X509Extension>();
        readonly List<Byte> _rawData = new List<Byte>();
        readonly X509AlternativeNameCollection _tsaName = new X509AlternativeNameCollection();
        DefaultSignedPkcs7 signedCms;
        Byte[] nonce;

        /// <summary>
        ///     Initializes a new instance of <strong>TspResponse</strong> class from ASN.1-encoded byte array.
        /// </summary>
        /// <param name="responseData">
        ///     ASN.1-encoded byte array returned by TSA server.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>responseData</strong> parameter is null.
        /// </exception>
        public TspResponse(Byte[] responseData) {
            if (responseData == null) {
                throw new ArgumentNullException(nameof(responseData));
            }
            decodeCms(new Asn1Reader(responseData));
        }

        /// <summary>
        /// Gets the status of Time-Stamp Response and additional information if error occured.
        /// </summary>
        public TspStatusInfo Status { get; private set; } = new TspStatusInfo();
        /// <summary>
        /// Gets the response type. This value is Time-Stamp Token Info (1.2.840.113549.1.9.16.1.4) or PKCS 7 Data (1.2.840.113549.1.7.1).
        /// </summary>
        public Oid ResponseType { get; private set; }
        /// <summary>
        /// Gets the Time-Stamp Response version. This value shall be set to 1.
        /// </summary>
        public Int32 Version { get; private set; }
        /// <summary>
        /// Gets or sets the TSA policy ID under which the timestamp was signed. This policy ID is TSA-specific.
        /// </summary>
        public Oid PolicyID { get; private set; }
        /// <summary>
        /// Gets the message to timestamp.
        /// </summary>
        public TspMessageImprint RequestMessage { get; private set; }
        /// <summary>
        /// Gets the serial number of response.
        /// </summary>
        public BigInteger SerialNumber { get; private set; }
        /// <summary>
        /// Gets the date and time when response was generated.
        /// </summary>
        public DateTime GenerationTimestamp { get; private set; }
        /// <summary>
        ///  Indicates whether the timestamp tokens from the same TSA can be ordered.
        /// </summary>
        /// <remarks>
        ///     If this member is set to <strong>false</strong>, then <see cref="GenerationTimestamp"/> only indicates the time at which
        ///     the timestamp token has been created by the TSA. In such a case, the ordering of timestamp tokens issued by the same TSA or
        ///     different TSAs is only possible when the difference between the <see cref="GenerationTimestamp"/> of the first timestamp token
        ///     and the <see cref="GenerationTimestamp"/> of the second timestamp token is greater than the sum of the accuracies of the
        ///     <see cref="GenerationTimestamp"/> for each token.
        /// <para>
        ///     If this member is set to <strong>true</strong>, every timestamp token from the same TSA can always be ordered based on the
        ///     <see cref="GenerationTimestamp"/> regardless of the <see cref="GenerationTimestamp"/> accuracy.
        /// </para>
        /// </remarks>
        public Boolean Ordering { get; private set; }
        /// <summary>
        /// Indicates whether a Nonce value was received along with response.
        /// </summary>
        public Boolean NonceReceived { get; private set; }
        /// <summary>
        /// Gets the name of TSA server. This property can be empty collection.
        /// </summary>
        public X509AlternativeNameCollection TsaName => new X509AlternativeNameCollection(_tsaName);
        /// <summary>
        /// Gets a collection of optional extensions associated with the current TSP request.
        /// </summary>
        public X509ExtensionCollection Extensions {
            get {
                var retValue = new X509ExtensionCollection();
                foreach (X509Extension extension in _extensions) {
                    retValue.Add(extension);
                }
                return retValue;
            }
        }
        /// <summary>
        /// Specifies the status of response.
        /// </summary>
        public TspValidationErrorStatus ResponseErrors { get; private set; }
        /// <summary>
        /// Specifies the certificate chain status.
        /// </summary>
        public X509ChainStatusFlags ChainErrors { get; private set; }
        /// <summary>
        /// Gets the ASN.1-encoded byte array that represents current Time-Stamp response object.
        /// </summary>
        public Byte[] RawData => _rawData.ToArray();

        void decodeCms(Asn1Reader asn) {
            asn.MoveNextAndExpectTags(48, (Byte)Asn1Type.OBJECT_IDENTIFIER);
            if (asn.Tag == 48) {
                Status = new TspStatusInfo(asn.GetTagRawData());
                if (Status.ResponseStatus != TspResponseStatus.Granted && Status.ResponseStatus != TspResponseStatus.GrantedWithModifications) {
                    return;
                }
                asn.MoveNextCurrentLevelAndExpectTags(48);
            } else {
                asn.MoveToPosition(0);
            }
            signedCms = new DefaultSignedPkcs7(asn.GetTagRawData());

            ResponseType = signedCms.ContentType;
            switch (ResponseType.Value) {
                // TimeStamp Token
                case "1.2.840.113549.1.9.16.1.4":
                    decodeTstInfo(new Asn1Reader(signedCms.Content));
                    break;
                // PKCS 7 DATA
                case "1.2.840.113549.1.7.1":
                    break;
            }
            getSigningTime();
            _rawData.AddRange(asn.GetRawData());
            validate();
        }
        void getSigningTime() {
            var timeAttr = signedCms.SignerInfos[0].AuthenticatedAttributes[SIGNING_TIME];
            if (timeAttr != null) {
                GenerationTimestamp = Asn1Utils.DecodeDateTime(timeAttr.RawData);
            }
        }
        void decodeTstInfo(Asn1Reader asn) {
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            Version = (Int32)new Asn1Integer(asn).Value;
            asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
            PolicyID = new Asn1ObjectIdentifier(asn).Value;
            asn.MoveNextAndExpectTags(48);
            RequestMessage = new TspMessageImprint(asn.GetTagRawData());
            asn.MoveNextCurrentLevelAndExpectTags((Byte)Asn1Type.INTEGER);
            SerialNumber = new Asn1Integer(asn).Value;
            asn.MoveNextAndExpectTags((Byte)Asn1Type.GeneralizedTime);
            GenerationTimestamp = new Asn1GeneralizedTime(asn).Value;

            decodeOptionalFields(asn);
        }
        void decodeOptionalFields(Asn1Reader asn) {
            while (asn.MoveNextCurrentLevel()) {
                switch (asn.Tag) {
                    case (Byte)Asn1Type.BOOLEAN:
                        Ordering = new Asn1Boolean(asn).Value;
                        break;
                    case (Byte)Asn1Type.INTEGER:
                        NonceReceived = true;
                        nonce = asn.GetPayload();
                        break;
                    case 48:
                        break;
                    case 0xa0:
                        Byte[] nameBytes = asn.GetTagRawData();
                        nameBytes[0] = 48;
                        _tsaName.Decode(nameBytes);
                        break;
                    case 0xa1:
                        Byte[] extBytes = asn.GetTagRawData();
                        extBytes[0] = 48;
                        var extList = new X509ExtensionCollection();
                        extList.Decode(asn.GetTagRawData());
                        foreach (X509Extension extension in extList) {
                            _extensions.Add(extension);
                        }
                        break;
                }
            }
        }
        void validate() {
            if (signedCms == null) {
                ResponseErrors |= TspValidationErrorStatus.NoResponse;
                return;
            }
            if (signedCms.Certificates.Count == 0) {
                ResponseErrors |= TspValidationErrorStatus.MissingSigningCertificate;
            }
            validateChain();
            validateSignature();
        }
        void validateNonce(TspRfc3161Request request) {
            if (request.UseNonce && !NonceReceived) {
                ResponseErrors |= TspValidationErrorStatus.MissingNonce;
            }
            if (request.UseNonce && NonceReceived) {
                Byte[] reqNonce = request.GetNonceBytes();
                Byte[] rspNonce = GetNonceBytes();
                if (reqNonce.Intersect(rspNonce).Count() != rspNonce.Length) {
                    ResponseErrors |= TspValidationErrorStatus.NonceMismatch;
                }
            }
        }
        void validateChain() {
            var chain = new X509Chain {
                ChainPolicy = {
                    VerificationTime = GenerationTimestamp
                }
            };
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(TSP_OID));
            chain.ChainPolicy.ExtraStore.AddRange(signedCms.Certificates);
            Boolean status = chain.Build(signedCms.Certificates[0]);
            if (!status) {
                ChainErrors = chain.ChainElements[0].ChainElementStatus[0].Status;
                if ((ChainErrors & X509ChainStatusFlags.NotValidForUsage) > 0) {
                    ResponseErrors |= TspValidationErrorStatus.SignerNotValidForUsage;
                }
            }
        }
        void validateSignature() {
            if (!signedCms.CheckSignature(true, false)) {
                ResponseErrors |= TspValidationErrorStatus.SignatureMismatch;
            }
        }

        /// <summary>
        /// Gets the byte array associated with the nonce value. If nonce is not received, an empty array is returned.
        /// </summary>
        /// <returns>
        /// A 16-byte long random byte array if nonce is received or 0-byte long array if nonce is not present.
        /// </returns>
        /// <remarks>
        /// If response does not contain nonce (<see cref="NonceReceived"/> is set to <strong>False</strong>), an empty array is returned.
        /// </remarks>
        public Byte[] GetNonceBytes() {
            return nonce == default
                ? new Byte[0]
                : nonce.ToArray();
        }

        /// <summary>
        /// Gets the signed CMS message associated with response. Returned object can be attached to Signed CMS signature in
        /// unauthenticated attributes like counter-signer.
        /// </summary>
        /// <returns>Signed CMS message if response was successful, otherwise <strong>null</strong>.</returns>
        public DefaultSignedPkcs7 GetSignedCms() {
            return signedCms == null
                ? null
                : new DefaultSignedPkcs7(signedCms.RawData);
        }

        /// <summary>
        /// Validates nonce in request and response.
        /// </summary>
        /// <param name="request">Request against which this response was produced.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>request</strong> parameter is null.
        /// </exception>
        /// <remarks>Nonce validation failure is added to <see cref="ResponseErrors"/> property.</remarks>
        public void ValidateNonce(TspRfc3161Request request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }
            validateNonce(request);
        }
    }
}
