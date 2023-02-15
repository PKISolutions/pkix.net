using System;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

namespace PKI.Exceptions {
	/// <summary>
	/// The exception that is thrown when attempting to perform read/write operations on Certification Authority (CA) server that is offline.
	/// </summary>
	/// <remarks>Use <see cref="Exception.Data"/> property to set exact error source.
	/// <para>PKI library uses <strong>Source</strong> key and value of <see cref="OfflineSource"/> value type.</para>
	/// </remarks>
	[Serializable, ComVisible(true)]
	public sealed class ServerUnavailableException : Exception {
		/// <summary>
		/// Initializes a new instance of the <strong>ServerUnavailableException</strong> class.
		/// </summary>
		public ServerUnavailableException() : base("Specified Certification Authority server is unavailable.") {
			HResult = unchecked((Int32)0x800706BA);
		}
		/// <param name="serverName">Specifies the CA server name.</param>
		public ServerUnavailableException(String serverName) : base("Specified Certification Authority '" + serverName + "' is unavailable.") {
			Server = serverName;
		}
		/// <param name="serverName">Specifies the CA server name.</param>
		/// <param name="message">A string that describes the error.</param>
		public ServerUnavailableException(String serverName, String message) : base(message) {
			Server = serverName;
		}
		/// <param name="message">The error message that explains the reason for the exception.</param>
		/// <param name="innerException">
		/// The exception that is the cause of the current exception. If the <strong>innerException</strong> parameter is not a null
		/// reference, the current exception is raised in a catch block that handles the inner exception.
		/// </param>
		public ServerUnavailableException(String message, Exception innerException) : base(message, innerException) { }
		/// <param name="info">The object that holds the serialized object data.</param>
		/// <param name="context">The contextual information about the source or destination.</param>
		/// <remarks>This constructor is called during deserialization to reconstitute the exception object transmitted over a stream.</remarks>
		public ServerUnavailableException(SerializationInfo info, StreamingContext context) : base(info, context) { }

		/// <summary>
		/// Gets the name of the CA server.
		/// </summary>
		public String Server {get; private set;}
	}
}
