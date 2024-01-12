using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CERTADMINLib;
using PKI.Structs;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateServices;
/// <summary>
/// Represents a collection of Key Recovery Agent (KRA) certificates assigned to the specified Certification Authority.
/// </summary>
public class KRA {
    String ConfigString;
    readonly List<X509Certificate2> _certs = new();

    /// <param name="certificateAuthority">Specifies an existing <see cref="CertificateServices"/> object.</param>
    /// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
    /// <exception cref="ServerUnavailableException">The CA server specified in the <strong>certificateAuthority</strong> parameter could not be contacted via RPC/DCOM protocol.</exception>
    public KRA(CertificateAuthority certificateAuthority) {
        if (String.IsNullOrEmpty(certificateAuthority.Name)) { throw new UninitializedObjectException(); }
        m_initialize(certificateAuthority);
    }

    /// <summary>
    /// Gets the common name of the Certification Authority in a sanitized form as specified in
    /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
    /// </summary>
    public String Name { get; private set; }
    /// <summary>
    /// Gets the display name of the Certification Authority (sanitized characters are decoded to textual characters).
    /// </summary>
    public String DisplayName { get; private set; }
    /// <summary>
    /// Gets the host fully qualified domain name (FQDN) of the server where Certification Authority is installed.
    /// </summary>
    public String ComputerName { get; private set; }
    /// <summary>
    /// Gets Key Recovery Agent (KRA) certificates assigned to CA server. If the property is empty, then CA server is not configured
    /// for key archival and all requests that require key archival will fail.
    /// </summary>
    public X509Certificate2Collection Certificate {
        get {
            X509Certificate2Collection certs = new X509Certificate2Collection();
            certs.AddRange(_certs.ToArray());
            return certs;
        }
    }
    /// <summary>
    /// Indicates whether the object was modified after it was instantiated.
    /// </summary>
    public Boolean IsModified { get; private set; }

    void m_initialize(CertificateAuthority certificateAuthority) {
        if (!certificateAuthority.IsEnterprise) { throw new PlatformNotSupportedException(); }
        if (!certificateAuthority.PingAdmin()) {
            var e = new ServerUnavailableException(certificateAuthority.DisplayName);
            e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
            throw e;
        }
        Name = certificateAuthority.Name;
        DisplayName = certificateAuthority.DisplayName;
        ComputerName = certificateAuthority.ComputerName;
        ConfigString = certificateAuthority.ConfigString;

        var CertAdmin = new CCertAdmin();
        Int32 KRACount = (Int32)CertAdmin.GetCAProperty(certificateAuthority.ConfigString, CertAdmConstants.CrPropKracertcount, 0, CertAdmConstants.ProptypeLong, 0);
        if (KRACount > 0) {
            for (Int32 index = 0; index < KRACount; index++) {
                String Base64 = (String)CertAdmin.GetCAProperty(certificateAuthority.ConfigString, CertAdmConstants.CrPropKracert, index, CertAdmConstants.ProptypeBinary, 1);
                _certs.Add(new X509Certificate2(Convert.FromBase64String(Base64)));
            }
        }
    }

    /// <summary>
    /// Adds key recovery agent (KRA) certificates to the CA. This method do not writes them to a Certification Authority.
    /// </summary>
    /// <param name="certs">One or more <see cref="X509Certificate2"/> object to add.</param>
    /// <exception cref="ArgumentNullException">The <strong>certs</strong> parameter is null or empty array.</exception>
    /// <remarks>
    /// If <see cref="Certificate"/> property already contains the certificate passed in <strong>certs</strong> parameter,
    /// the method skips the certificate.
    /// </remarks>
    public void Add(X509Certificate2[] certs) {
        if (certs == null || certs.Length == 0) { throw new ArgumentNullException(nameof(certs)); }

        Int32 before = _certs.Count;
        var chain = new X509Chain();
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.4.1.311.21.6"));
        foreach (X509Certificate2 cert in certs.Where(chain.Build)) {
            if (
                !String.IsNullOrEmpty(cert.Thumbprint) &&
                Certificate.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count == 0
            ) {
                _certs.Add(cert);
            }
            chain.Reset();
        }
        if (_certs.Count > before) { IsModified = true; }
    }
    /// <summary>
    /// Removes certificate(s) from <see cref="Certificate"/> property by it's Thumbprint value.
    /// </summary>
    /// <param name="thumbprint">One or more certificate thumbprint values to identify certificates to remove.</param>
    public void Remove(String[] thumbprint) {
        if (thumbprint == null) {
            Certificate.Clear();
            IsModified = true;
        } else {
            var certs2 = new List<X509Certificate2>();
            certs2.AddRange(_certs);
            if (certs2.Count > 0) {
                foreach (X509Certificate2 cert in from cert in certs2 from thumb in thumbprint.Where(thumb => cert.Thumbprint == thumb.ToUpper().Replace(" ", null)) select cert) {
                    IsModified = true;
                    _certs.Remove(cert);
                }
            }
            certs2.Clear();
        }
    }
    /// <summary>
    /// Removes certificate(s) from <see cref="Certificate"/> property by it's Thumbprint value.
    /// </summary>
    /// <param name="cert">An <see cref="X509Certificate2"/> object to remove.</param>
    public void Remove(X509Certificate2 cert) {
        var certs2 = new List<X509Certificate2>();
        certs2.AddRange(_certs);
        if (certs2.Any(cert2 => cert2.Thumbprint == cert.Thumbprint)) {
            IsModified = true;
            _certs.Remove(cert);
            certs2.Clear();
        }
    }
    /// <summary>
    /// Updates KRA configuration by writing KRA certificates to Certification Authority. The method writes all certificates contained in
    /// <see cref="Certificate"/> property.
    /// </summary>
    /// <param name="restart">
    /// Indicates whether to restart certificate services to immediately apply changes. Updated settings has no effect until
    /// CA service is restarted.
    /// </param>
    ///  <exception cref="UnauthorizedAccessException">
    /// The caller do not have sufficient permissions to make changes in the CA configuration.
    /// </exception>
    /// <exception cref="ServerUnavailableException">
    /// The target CA server could not be contacted via RPC/DCOM transport.
    /// </exception>
    /// <remarks>
    /// <para>This method do not check whether the certificates in <see cref="Certificate"/> property are valid.
    /// The caller is responsible to check if the certificates are time-valid, trusted and not revoked.</para>
    /// </remarks>
    /// <returns>
    /// <strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
    /// and the method returns <strong>False</strong>.
    /// </returns>
    /// <remarks>The caller must have <strong>Administrator</strong> permissions on the target CA server.</remarks>
    public Boolean SetInfo(Boolean restart) {
        if (IsModified) {
            if (!CertificateAuthority.Ping(ComputerName)) {
                var e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
                throw e;
            }
            var CertAdmin = new CCertAdmin();
            try {
                if (_certs.Count > 0) {
                    Int32 kraCount = (Int32)CertAdmin.GetCAProperty(ConfigString, CertAdmConstants.CrPropKracertcount, 0, CertAdmConstants.ProptypeLong, 0);
                    if (kraCount > 0) { CertAdmin.SetCAProperty(ConfigString, CertAdmConstants.CrPropKracertcount, 0, CertAdmConstants.ProptypeLong, 0); }
                    for (Int32 index = 0; index < _certs.Count; index++) {
                        String der = CryptographyUtils.EncodeDerString(_certs[index].RawData);
                        CertAdmin.SetCAProperty(ConfigString, CertAdmConstants.CrPropKracert, index, CertAdmConstants.ProptypeBinary, der);
                    }
                    CertAdmin.SetCAProperty(ConfigString, CertAdmConstants.CrPropKracertusedcount, 0, CertAdmConstants.ProptypeLong, _certs.Count);
                } else {
                    CertAdmin.SetCAProperty(ConfigString, CertAdmConstants.CrPropKracertcount, 0, CertAdmConstants.ProptypeLong, 0);
                    CertAdmin.SetCAProperty(ConfigString, CertAdmConstants.CrPropKracertusedcount, 0, CertAdmConstants.ProptypeLong, 0);
                }
            } catch (Exception e) {
                throw ErrorHelper.ComExceptionHandler(e);
            } finally {
                CryptographyUtils.ReleaseCom(CertAdmin);
            }
            IsModified = false;
            if (restart) { CertificateAuthority.Restart(ComputerName); }
            return true;
        }
        return false;
    }
}
