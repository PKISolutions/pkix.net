using System;
using System.Runtime.InteropServices;

namespace PKI.Structs {
	/// <summary>
	/// <strong>Certbcli</strong> class represents a set of unmanaged structures that are translated to .NET Framework compatible
	/// structures.
	/// <p>This class do not provide any constructors and static methods.</p>
	/// </summary>
	/// <remarks>Most of these structures are related to <strong>CryptoAPI</strong> and are defined in <strong>Certbcli.h</strong>
	/// header file.</remarks>
	public class Certbcli {
		[StructLayout(LayoutKind.Sequential)]
		public struct CSEDB_RSTMAP {
			public String pwszDatabaseName;
			public String pwszNewDatabaseName;
		}
	}
}
