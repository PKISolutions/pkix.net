using System;

namespace PKI.Exceptions {
	/// <summary>
	/// Gets 'offline' exception sources enumeration.
	/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
	/// </summary>
	[Flags]
	public enum OfflineSource {
		/// <summary>
		/// Identifies the RPC/DCOM communication issue when client cannot establish a communication to a remote server
		/// over RPC/DCOM. Usually this is caused due to network connectivity, firewall restrictions or when target service
		/// is not started.
		/// </summary>
		DCOM		= 1,
		/// <summary>
		/// Identifies the remote registry access issue.
		/// </summary>
		Registry	= 2,
		/// <summary>
		/// Identifies the both, RPC/DCOM and remote registry communication issue.
		/// </summary>
		All         = DCOM | Registry
	}
}
