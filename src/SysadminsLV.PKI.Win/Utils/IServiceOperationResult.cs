using System;

namespace SysadminsLV.PKI.Utils;
/// <summary>
/// Defines general-purpose interface to indicate the status of the operation.
/// </summary>
public interface IServiceOperationResult {
    /// <summary>
    /// Gets the Win32-style HRESULT error code. Zero value means success, non-zero value means failure.
    /// </summary>
    Int32 HResult { get; }
    /// <summary>
    /// Gets the message associated with the <see cref="HResult"/> error code.
    /// </summary>
    String StatusMessage { get; }
    /// <summary>
    /// Gets or sets the object which is the result of the operation. This member is not mandatory and may
    /// return <strong>null</strong> even if the status is successful and depends.
    /// </summary>
    Object InnerObject { get; set; }
}