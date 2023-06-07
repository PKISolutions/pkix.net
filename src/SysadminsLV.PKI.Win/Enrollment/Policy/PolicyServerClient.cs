using System;
using System.Collections;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using Interop.CERTENROLLLib;
using PKI.CertificateTemplates;
using PKI.Exceptions;
using SysadminsLV.PKI.Utils;

namespace PKI.Enrollment.Policy;
/// <summary>
/// Represents a enrollment policy server client object.
/// </summary>
public class PolicyServerClient {
    Boolean registered;
    CX509EnrollmentPolicyWebService policy;
    String uName, name;
    SecureString uPassword;
    Int32 priority;
    PolicyAuthenticationEnum authentication;
    PolicyServerUrlFlagsEnum flags;

    internal PolicyServerClient(IX509PolicyServerUrl serverManager, Boolean userContext) {
        if (((Int32)serverManager.Flags & (Int32)PolicyServerUrlFlags.PsfLocationGroupPolicy) != 0) {
            FromPolicy = true;
        }
        priority = (Int32)serverManager.Cost;
        Name = serverManager.GetStringProperty(PolicyServerUrlPropertyID.PsFriendlyName);
        Flags = (PolicyServerUrlFlagsEnum)serverManager.Flags;
        m_initialize2(serverManager.Url, userContext, (PolicyAuthenticationEnum)serverManager.AuthFlags, true);
    }

    /// <param name="url">Specifies the certificate enrollment policy server endpoint URL.</param>
    /// <param name="userContext">Specifies whether the policy is intended for user or computer context.</param>
    /// <param name="authentication">Specifies the authentication type used for the policy server.</param>
    /// <param name="userName">
    /// Specifies the user name to authenticate in enrollment policy server.
    /// <para>If the authentication type is set to <strong>ClientCertificate</strong>, this parameter must contains
    /// authentication certificate's thumbprint.</para>
    /// <para>This parameter must be omitted when <strong>Kerberos</strong> authentication is used.</para>
    /// </param>
    /// <param name="password">
    /// Specifies the password to authenticate in enrollment policy server.
    /// <para>This parameter must be used only when <strong>UserNameAndPassword</strong> authentication
    /// method is used. This parameter must be omitted in all other authentication methods.</para>
    /// </param>
    /// <exception cref="ArgumentNullException">The <strong>url</strong> parameter is null.</exception>
    /// <exception cref="NotSupportedException">The operating system do not support certificate enrollment policy servers.</exception>
    public PolicyServerClient(String url, Boolean userContext, PolicyAuthenticationEnum authentication, String userName, SecureString password) {
        if (String.IsNullOrEmpty(url)) {
            throw new ArgumentNullException(nameof(url));
        }
        registered = false;
        uName = userName;
        uPassword = password;
        m_initialize2(url, userContext, authentication, false);
    }

    /// <summary>
    /// Gets or sets the enrollment policy friendly name.
    /// </summary>
    public String Name {
        get => name;
        set {
            set_property("Name", value);
            name = value;
        }
    }
    /// <summary>
    /// Gets the enrollment policy unique ID.
    /// </summary>
    public String PolicyId { get; private set; }
    /// <summary>
    /// Gets the enrollment policy URL.
    /// </summary>
    public Uri URL { get; private set; }
    /// <summary>
    /// Gets or sets the enrollment policy authentication type.
    /// </summary>
    public PolicyAuthenticationEnum Authentication {
        get { return authentication; }
        set {
            set_property("Authentication", value);
            authentication = value;
        }
    }

    /// <summary>
    /// Gets or sets the enrollment policy priority. The lower number means higher priority.
    /// </summary>
    public Int32 Priority {
        get { return priority; }
        set {
            set_property("Priority", value);
            priority = value;
        }
    }
    /// <summary>
    /// Gets or sets enrollment policy settings.
    /// </summary>
    public PolicyServerUrlFlagsEnum Flags {
        get { return flags; }
        set {
            set_property("Flags", value);
            flags = value;
        }
    }

    /// <summary>
    /// Gets the path to a enrollment policy local configuration.
    /// </summary>
    public String FilePath { get; private set; }
    /// <summary>
    /// Specifies whether the enrollment policy is registered in user or machine context.
    /// </summary>
    public Boolean UserContext { get; private set; }
    /// <summary>
    /// Specifies whether the current policy object is registered via group policy or via local registry.
    /// </summary>
    public Boolean FromPolicy { get; }
    /// <summary>
    /// Indicates whether the policy is loaded.
    /// </summary>
    public Boolean PolicyLoaded { get; private set; }
    /// <summary>
    /// Gets the list of certificate templates available for the enrollment. This property is filled
    /// when <see cref="LoadPolicy"/> method is called.
    /// </summary>
    public CertificateTemplate[] Templates { get; private set; }

    void m_initialize2(String url, Boolean userContext, PolicyAuthenticationEnum auth, Boolean Private) {
        policy = new CX509EnrollmentPolicyWebService();
        try {
            if (!Private) {
                switch (auth) {
                    case PolicyAuthenticationEnum.UserNameAndPassword:
                        policy.SetCredential(0, (X509EnrollmentAuthFlags)auth, uName, Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(uPassword)));
                        break;
                    case PolicyAuthenticationEnum.ClientCertificate:
                        policy.SetCredential(0, (X509EnrollmentAuthFlags)auth, uName, null);
                        break;
                }
            }
            X509CertificateEnrollmentContext context = userContext
                                                           ? X509CertificateEnrollmentContext.ContextUser
                                                           : X509CertificateEnrollmentContext.ContextMachine;
            policy.Initialize(url, null, (X509EnrollmentAuthFlags)auth, false, context);
            try {
                policy.LoadPolicy(X509EnrollmentPolicyLoadOption.LoadOptionDefault);
            } catch { }
            try {
                Name = policy.GetFriendlyName();
            } catch { }
            PolicyId = policy.GetPolicyServerId();
            URL = new Uri(url);
            Authentication = auth;
            FilePath = policy.GetCachePath();
            UserContext = userContext;
        } catch (Exception e) {
            throw ErrorHelper.ComExceptionHandler(e);
        } finally {
            CryptographyUtils.ReleaseCom(policy);
        }
    }
    void get_templates() {
        Templates = (from IX509CertificateTemplate temp in policy.GetTemplates() select new CertificateTemplate(temp)).ToArray();
    }
    void set_property(String propName, Object propValue) {
        if (FromPolicy) { return; }
        if (propValue == null) { return; }
        CX509PolicyServerListManager serverManager = new CX509PolicyServerListManager();
        X509CertificateEnrollmentContext context = UserContext
                                                       ? X509CertificateEnrollmentContext.ContextUser
                                                       : X509CertificateEnrollmentContext.ContextMachine;
        try {
            serverManager.Initialize(context, PolicyServerUrlFlags.PsfLocationRegistry);
            IEnumerator enumerator = serverManager.GetEnumerator();
            do {
                if (enumerator.Current != null) {
                    if (((IX509PolicyServerUrl)enumerator.Current).GetStringProperty(PolicyServerUrlPropertyID.PsPolicyID) == PolicyId) {
                        switch (propName) {
                            case "Name":
                                ((IX509PolicyServerUrl)enumerator.Current).SetStringProperty(PolicyServerUrlPropertyID.PsFriendlyName, (String)propValue);
                                break;
                            case "Priority":
                                ((IX509PolicyServerUrl)enumerator.Current).Cost = (UInt32)propValue;
                                break;
                            case "Authentication":
                                ((IX509PolicyServerUrl)enumerator.Current).AuthFlags = (X509EnrollmentAuthFlags)propValue;
                                break;
                            case "Flags":
                                ((IX509PolicyServerUrl)enumerator.Current).Flags = (PolicyServerUrlFlags)propValue;
                                break;
                        }
                        ((IX509PolicyServerUrl)enumerator.Current).UpdateRegistry(context);
                        CryptographyUtils.ReleaseCom(serverManager);
                        return;
                    }
                }
            } while (enumerator.MoveNext());
        } finally {
            CryptographyUtils.ReleaseCom(serverManager);
        }
    }

    /// <summary>
    /// Loads certificate templates available for enrollment. Certificate templates are populated in
    /// <see cref="Templates"/> property if the method succeeds.
    /// </summary>
    /// <param name="userName">
    /// Specifies the user name to authenticate in enrollment policy server.
    /// <para>If the authentication type is set to <strong>ClientCertificate</strong>, this parameter must contains
    /// authentication certificate's thumbprint.</para>
    /// <para>This parameter must be omitted when <strong>Kerberos</strong> authentication is used.</para>
    /// </param>
    /// <param name="password">
    /// Specifies the password to authenticate in enrollment policy server.
    /// <para>This parameter must be used only when <strong>UserNameAndPassword</strong> authentication
    /// method is used. This parameter must be omitted in all other authentication methods.</para>
    /// </param>
    public void LoadPolicy(String userName = null, SecureString password = null) {
        if (String.IsNullOrEmpty(URL.AbsoluteUri)) { throw new UninitializedObjectException(); }
        if (!String.IsNullOrEmpty(userName)) { uName = userName; }
        if (password != null) { uPassword = password; }
        policy = new CX509EnrollmentPolicyWebService();
        try {
            if (!String.IsNullOrEmpty(uName)) {
                switch (Authentication) {
                    case PolicyAuthenticationEnum.UserNameAndPassword:
                        policy.SetCredential(0, (X509EnrollmentAuthFlags)Authentication, uName, Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(uPassword)));
                        break;
                    case PolicyAuthenticationEnum.ClientCertificate:
                        policy.SetCredential(0, (X509EnrollmentAuthFlags)Authentication, uName, null);
                        break;
                }
            }
            X509CertificateEnrollmentContext context = UserContext
                ? X509CertificateEnrollmentContext.ContextUser
                : X509CertificateEnrollmentContext.ContextMachine;
            policy.Initialize(URL.AbsoluteUri, PolicyId, (X509EnrollmentAuthFlags)Authentication, false, context);
            policy.LoadPolicy(X509EnrollmentPolicyLoadOption.LoadOptionDefault);
            get_templates();
            PolicyLoaded = true;
        } catch (Exception e) {
            throw ErrorHelper.ComExceptionHandler(e);
        }
    }
    ///  <summary>
    ///		Registers or updates a current object in local registry.
    ///  </summary>
    /// <exception cref="UninitializedObjectException">
    ///		The current object is not properly initialized through any of public constructor.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// 	<strong>Authentication</strong> property is set to <strong>None</strong>.
    ///  </exception>
    public void Register() {
        if (URL == null) { throw new UninitializedObjectException(); }
        CX509EnrollmentHelper urlClass = new CX509EnrollmentHelper();
        urlClass.Initialize(UserContext
            ? X509CertificateEnrollmentContext.ContextUser
            : X509CertificateEnrollmentContext.ContextMachine);
        try {
            switch (Authentication) {
                case PolicyAuthenticationEnum.Anonymous: case PolicyAuthenticationEnum.Kerberos:
                    urlClass.AddPolicyServer(
                        URL.AbsoluteUri,
                        PolicyId,
                        0,
                        (X509EnrollmentAuthFlags)(Int32)Authentication,
                        null,
                        null
                    );
                    break;
                case PolicyAuthenticationEnum.UserNameAndPassword:
                    urlClass.AddPolicyServer(
                        URL.AbsoluteUri,
                        PolicyId,
                        0,
                        (X509EnrollmentAuthFlags)(Int32)Authentication,
                        uName,
                        Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(uPassword))
                    );
                    break;
                case PolicyAuthenticationEnum.ClientCertificate:
                    urlClass.AddPolicyServer(
                        URL.AbsoluteUri,
                        PolicyId,
                        0,
                        (X509EnrollmentAuthFlags)(Int32)Authentication,
                        uName,
                        null
                    );
                    break;
                default: throw new NotSupportedException();
            }
            registered = true;
        } catch (Exception e) {
            throw ErrorHelper.ComExceptionHandler(e);
        } finally {
            CryptographyUtils.ReleaseCom(urlClass);
        }
    }
    /// <summary>
    /// Unregisters (deletes) certificate enrollment policy server endpoint from registry.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    ///		The current CEP object is not registered.
    /// </exception>
    /// <exception cref="UninitializedObjectException">
    ///		The current object is not properly initialized through any of public constructor.
    /// </exception>
    public void Unregister() {
        if (URL == null) { throw new UninitializedObjectException(); }
        if (!registered) { throw new InvalidOperationException("The current CEP object is not registered."); }
        CX509PolicyServerUrl urlClass = new CX509PolicyServerUrl();
        urlClass.Initialize(UserContext
            ? X509CertificateEnrollmentContext.ContextUser
            : X509CertificateEnrollmentContext.ContextMachine);
        try {
            urlClass.AuthFlags = (X509EnrollmentAuthFlags)(Int32)Authentication;
            urlClass.Cost = (UInt32)Priority;
            urlClass.Flags = (PolicyServerUrlFlags)Flags;
            urlClass.Url = URL.AbsoluteUri;
            if (!String.IsNullOrEmpty(Name)) { urlClass.SetStringProperty(PolicyServerUrlPropertyID.PsFriendlyName, Name); }
            urlClass.SetStringProperty(PolicyServerUrlPropertyID.PsPolicyID, PolicyId);
            urlClass.RemoveFromRegistry(UserContext
                ? X509CertificateEnrollmentContext.ContextUser
                : X509CertificateEnrollmentContext.ContextMachine);
        } catch (Exception e) {
            throw ErrorHelper.ComExceptionHandler(e);
        } finally {
            CryptographyUtils.ReleaseCom(urlClass);
        }
    }
    /// <summary>
    /// Validates the current policy information.
    /// </summary>
    /// <returns><strong>True</strong> if the policy is in a valid state, otherwise <strong>False</strong>.</returns>
    public Boolean Validate() {
        if (policy == null) { throw new UninitializedObjectException(); }
        try {
            policy.Validate();
            return true;
        } catch {
            return false;
        }
    }
    /// <summary>
    /// Sets the credential used to contact the certificate enrollment policy (CEP) server
    /// </summary>
    /// <param name="userName">
    ///		Specifies the user name to authenticate in enrollment policy server.
    ///		<para>
    ///			If the authentication type is set to <strong>ClientCertificate</strong>, this parameter must contains
    ///			authentication certificate's thumbprint.
    ///		</para>
    /// <para>This parameter must be omitted when <strong>Kerberos</strong> authentication is used.</para>
    /// </param>
    /// <param name="password">
    ///		Specifies the password to authenticate in enrollment policy server.
    ///		<para>
    ///			This parameter must be used only when <strong>UserNameAndPassword</strong> authentication
    ///			method is used. This parameter must be omitted in all other authentication methods.
    ///		</para>
    /// </param>
    /// <exception cref="ArgumentNullException"><strong>userName</strong> parameter is null reference.</exception>
    /// <remarks>
    ///		Currently this method do not set or update credentials in the credential vault, only default
    ///		class constructor combining with <see cref="Register"/> method provides this functionality.
    /// </remarks>
    public void SetCredential(String userName, SecureString password) {
        if (String.IsNullOrEmpty(userName)) { throw new ArgumentNullException(nameof(userName)); }
        if (URL == null) { throw new UninitializedObjectException(); }
        uName = userName;
        uPassword = password;
        switch (Authentication) {
            case PolicyAuthenticationEnum.UserNameAndPassword:
                policy.SetCredential(0, (X509EnrollmentAuthFlags)Authentication, userName, Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(password)));
                break;
            case PolicyAuthenticationEnum.ClientCertificate:
                policy.SetCredential(0, (X509EnrollmentAuthFlags)Authentication, userName, null);
                break;
        }
    }
}
