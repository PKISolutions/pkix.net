using System;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents Time-Stamp Response status information.
/// </summary>
public class TspStatusInfo {
    internal TspStatusInfo() {
            
    }
    internal TspStatusInfo(Byte[] rawData) {
        decode(new Asn1Reader(rawData));
    }
        
    /// <summary>
    /// Gets the response status.
    /// </summary>
    public TspResponseStatus ResponseStatus { get; private set; }
    /// <summary>
    /// Gets the detailed response error code when request was not successful.
    /// </summary>
    public TspFailureStatus ErrorCode { get; private set; }
    /// <summary>
    /// Gets an optional error message returned from server when request was not successful.
    /// </summary>
    public String ErrorText { get; private set; }

    void decode(Asn1Reader asn) {
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        ResponseStatus = (TspResponseStatus)(Int32)new Asn1Integer(asn).Value;
        while (asn.MoveNextSibling()) {
            switch (asn.Tag) {
                case (Byte)Asn1Type.INTEGER:
                    ErrorCode = (TspFailureStatus)((Int32)new Asn1Integer(asn).Value + 1);
                    break;
                case (Byte)Asn1Type.UTF8String:
                    ErrorText = Encoding.UTF8.GetString(asn.GetPayload());
                    break;
                        
            }
        }
    }
}