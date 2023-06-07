using System;
using System.Text;
using CERTADMINLib;
using PKI.CertificateTemplates;
using PKI.Structs;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Dcom.Implementations;
/// <summary>
/// Represents a Windows-specific implementation of <see cref="ICertPropWriterD"/> interface.
/// </summary>
class CertPropWriterD : ICertPropWriterD {
    readonly String _configString;

    public CertPropWriterD(String configString) {
        _configString = configString;
    }

    /// <inheritdoc />
    public void SetTemplates(CertificateTemplate[] templates) {
        if (templates == null) {
            throw new ArgumentNullException(nameof(templates));
        }

        var sb = new StringBuilder();
        foreach (CertificateTemplate item in templates) {
            sb.Append(item.Name + "\n");
            sb.Append(item.OID.Value + "\n");
        }

        var certAdmin = new CCertAdmin();
        try {
            certAdmin.SetCAProperty(_configString, CertAdmConstants.CrPropTemplates, 0, CertAdmConstants.ProptypeString, sb.ToString());
        } catch (Exception e) {
            throw ErrorHelper.ComExceptionHandler(e);
        }
    }
}