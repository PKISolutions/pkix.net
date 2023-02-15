using System;

namespace PKI.CertificateServices.Flags {
	/// <summary>
	/// Defines CA management and request flags.
	/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
	/// </summary>
	[Flags]
	public enum InterfaceFlagEnum {
		/// <summary>
		/// No flags are defined.
		/// </summary>
		None						= 0x00000000,	// 0
		/// <summary>
		/// The behavior for this flag is not defined and it should not be used.
		/// </summary>
		LockICertRequest			= 0x00000001,	// 1
		/// <summary>
		/// The CA will not issue any certificates or hold pending any requests for remote users.
		/// </summary>
		NoRemoteICertRequest		= 0x00000002,	// 2
		/// <summary>
		/// The CA will not issue any certificates or hold pending any requests for local users.
		/// </summary>
		NoLocalICertRequest			= 0x00000004,	// 4
		/// <summary>
		/// The CA will not issue any certificates or hold pending any requests for callers using the ICertPassage interface.
		/// </summary>
		NoRPCICertRequest			= 0x00000008,	// 8
		/// <summary>
		/// No access to Certificate Services Remote Administration Protocol methods for remote callers.
		/// </summary>
		NoRemoteICertAdmin			= 0x00000010,	// 16
		/// <summary>
		/// No access to Certificate Services Remote Administration Protocol methods for local callers.
		/// </summary>
		NoLocalICertAdmin			= 0x00000020,	// 32
		/// <summary>
		/// The CA restricts access to the backup-related methods of this protocol for remote callers.
		/// </summary>
		NoRemoteICertAdminBackup	= 0x00000040,	// 64
		/// <summary>
		/// The CA restricts access to the backup-related methods of this protocol for local callers.
		/// </summary>
		NoLocalICertAdminBackup		= 0x00000080,	// 128
		/// <summary>
		/// The database files cannot be backed up using a mechanism other than the methods of the ICertAdmin2 interface.
		/// </summary>
		NoSnapshotBackup			= 0x00000100,	// 256
		/// <summary>
		/// a RPC security settings (defined in <see href="http://msdn.microsoft.com/en-us/library/cc243867(PROT.10).aspx">2.2.1.1.8 Authentication Levels</see>)
		/// should be defined for all RPC connections to the server for certificate-request operations
		/// </summary>
		EnforceEncryptICertRequest	= 0x00000200,	// 512
		/// <summary>
		/// a RPC security settings (defined in <see href="http://msdn.microsoft.com/en-us/library/cc243867(PROT.10).aspx">2.2.1.1.8 Authentication Levels</see>)
		/// should be defined for all RPC connections to the server for certificate administrative operations (the methods defined in the ICertAdmin2 interface).
		/// </summary>
		EnforceEncryptICertAdmin	= 0x00000400,	// 1024
		/// <summary>
		/// Enables an exit algorithm to retrieve the Encrypted private-Key Blob.
		/// </summary>
		EnableExitKeyRetrieval		= 0x00000800,	// 2048
		/// <summary>
		/// Only CA administrators can update the CA audit filter settings.
		/// </summary>
		EnableAdminAsAuditor		= 0x00001000	// 4096
	}
}
