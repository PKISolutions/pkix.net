using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using CERTADMINLib;
using PKI.Structs;
using SysadminsLV.PKI.Structs;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Dcom.Implementations;

/// <summary>
/// Represents a Windows-specific implementation of <see cref="ICertRequestAdmin"/> interface.
/// </summary>
public class CertRequestAdminD : ICertRequestAdmin {
    readonly String _configString;

    /// <summary>
    /// Initializes a new instance of <strong>CertRequestAdminD</strong> class from Certification Authority configuration string.
    /// </summary>
    /// <param name="configString">Certification Authority configuration string.</param>
    public CertRequestAdminD(String configString) {
        _configString = configString;
    }

    /// <inheritdoc />
    public void SetCertificateExtension(Int32 requestID, X509Extension extension) {
        if (extension == null) {
            throw new ArgumentNullException(nameof(extension));
        }

        ICertAdmin2 certAdmin = CertAdminFactory.CreateICertAdmin();
        // BSTR is length-prefixed type, so allocate extra 4 bytes to store BSTR length
        IntPtr pbBstr = Marshal.AllocHGlobal(extension.RawData.Length + 4);
        // write length in front of actual BSTR value
        Marshal.WriteInt32(pbBstr, 0, extension.RawData.Length);
        // copy raw bytes right after length prefix
        Marshal.Copy(extension.RawData, 0, pbBstr + 4, extension.RawData.Length);
        // create an instance of VARIANT and configure it
        var variant = new OleAut.VARIANT {
            vt = OleAut.VT_BSTR,
            // the pointer to BSTR doesn't include prefix length, so skip 4 bytes
            pvRecord = pbBstr + 4
        };
        Int32 flags = extension.Critical ? 1 : 0;

        IntPtr pvarValue = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(OleAut.VARIANT)));
        Marshal.StructureToPtr(variant, pvarValue, false);
        try {
            certAdmin.SetCertificateExtension(_configString, requestID, extension.Oid.Value, CertAdmConstants.ProptypeBinary, flags, pvarValue);
        } finally {
            Marshal.FreeHGlobal(pbBstr);
            Marshal.FreeHGlobal(pvarValue);
            CryptographyUtils.ReleaseCom(certAdmin);
        }
    }
}
