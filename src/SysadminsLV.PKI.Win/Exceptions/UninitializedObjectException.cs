using System;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

namespace PKI.Exceptions {
	/// <summary>
	/// The exception that is thrown when unitialized object is attempted to be accessed.
	/// <para>Usually this exception is thrown when accessing cryptography objects with null or invalid handle.
	/// Also this exception is thrown when cryptographic object is created, but not properly initialized.
	/// </para>
	/// </summary>
	[Serializable, ComVisible(true)]
	public sealed class UninitializedObjectException : Exception {
		/// <summary>
		/// Initializes a new instance of the <strong>UninitializedObjectException</strong> class.
		/// </summary>
		public UninitializedObjectException() : base("An attempt was made to access an uninitialized object.") { }
		/// <param name="message">A string that describes the error.</param>
		public UninitializedObjectException(String message) : base(message) { }
		/// <param name="message">The error message that explains the reason for the exception.</param>
		/// <param name="innerException">
		/// The exception that is the cause of the current exception. If the <strong>innerException</strong> parameter is not a null
		/// reference, the current exception is raised in a catch block that handles the inner exception.
		/// </param>
		public UninitializedObjectException(String message, Exception innerException) : base(message,innerException) { }
		/// <param name="info">The object that holds the serialized object data.</param>
		/// <param name="context">The contextual information about the source or destination.</param>
		/// <remarks>This constructor is called during deserialization to reconstitute the exception object transmitted over a stream.</remarks>
		public UninitializedObjectException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}
}
