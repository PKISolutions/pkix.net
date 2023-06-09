using System;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Provides an abstract class that represents a Time-Stamp Request object.
/// </summary>
public abstract class TspRequest {

    /// <summary>
    /// Initializes a new instance of <strong>TspRequest</strong> from an object identifier that specifies the request type.
    /// </summary>
    /// <param name="requestType"></param>
    protected TspRequest(Oid requestType) {
        RequestType = requestType;
    }

    /// <summary>
    /// Gets the identifier of TSP request type.
    /// </summary>
    public Oid RequestType { get; }
    /// <summary>
    /// Gets or sets the url to a Time-Stamping Authority.
    /// </summary>
    public Uri TsaUrl { get; set; }
    /// <summary>
    /// Gets or sets web proxy information that will be used to connect to TSA server.
    /// </summary>
    public WebProxy Proxy { get; set; }
    /// <summary>
    /// Gets or sets the network credentials that are sent to a TSA server and used to authenticate the request.
    /// </summary>
    /// <remarks>
    ///		TSA servers should not use authentication for incoming requests.
    /// </remarks>
    public ICredentials Credentials { get; set; }


        
    /// <summary>
    /// Adds required headers to web client.
    /// </summary>
    /// <param name="wc">Web client instance.</param>
    protected static void PrepareWebClient(WebClient wc) {
        Version ver = Assembly.GetExecutingAssembly().GetName().Version;
        wc.Headers.Add("Content-Type", "application/timestamp-query");
        wc.Headers.Add("Accept", "application/timestamp-reply");
        wc.Headers.Add("User-Agent", $"PKIX.NET/{ver}");
        wc.Headers.Add("Cache-Control", "no-cache");
        wc.Headers.Add("Pragma", "no-cache");
    }
        
    /// <summary>
    /// Encodes current request state to a ASN.1-encoded byte array.
    /// </summary>
    /// <returns>ASN.1-encoded byte array.</returns>
    public abstract Byte[] Encode();
    /// <summary>
    /// Sends request to specified TSA server and returns response.
    /// </summary>
    /// <returns>
    /// Time-Stamp Response.
    /// </returns>
    public abstract TspResponse SendRequest();
}