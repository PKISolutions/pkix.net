using System;

namespace SysadminsLV.PKI.Utils;
/// <summary>
/// Defines general-purpose class to indicate the status of the operation.
/// </summary>
public class ServiceOperationResult : IServiceOperationResult {
    /// <summary>
    /// Initializes a new instance of <strong>ServiceOperationResult</strong> from Win32 HRESULT status code.
    /// Status message is decoded automatically.
    /// </summary>
    /// <param name="hresult">32-bit Win32 HRESULT status code.</param>
    public ServiceOperationResult(Int32 hresult) {
        HResult = hresult;
        StatusMessage = ErrorHelper.GetMessage(hresult);
    }
    /// <summary>
    /// Initializes a new instance of <strong>ServiceOperationResult</strong> from Win32 HRESULT status code
    /// and custome status message.
    /// </summary>
    /// <param name="hresult">32-bit Win32 HRESULT status code.</param>
    /// <param name="message">Custom status message for specified status code.</param>
    public ServiceOperationResult(Int32 hresult, String message) {
        HResult = hresult;
        StatusMessage = message;
    }
    /// <summary>
    /// Initializes a new instance of <strong>ServiceOperationResult</strong> from Win32 HRESULT status code
    /// and custome status message.
    /// </summary>
    /// <param name="hresult">32-bit Win32 HRESULT status code.</param>
    /// <param name="message">Custom status message for specified status code.</param>
    /// <param name="obj">Custom object associated with the current operation status.</param>
    public ServiceOperationResult(Int32 hresult, String message, Object obj) {
        HResult = hresult;
        StatusMessage = message;
        InnerObject = obj;
    }

    /// <inheritdoc />
    public Int32 HResult { get; }
    /// <inheritdoc />
    public String StatusMessage { get; }
    /// <inheritdoc />
    public Object InnerObject { get; set; }
}