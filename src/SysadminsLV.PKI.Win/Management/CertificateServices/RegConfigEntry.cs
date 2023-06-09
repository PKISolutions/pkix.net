using System;
using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a Certification Authority configuration entry to commit. This object is used in <see cref="CertSrvConfig.OnCommit"/> method.
    /// </summary>
    public class RegConfigEntry {
        /// <summary>
        /// Initializes a new instance of <strong>RegConfigEntry</strong> class using value name, optional node path and value to write.
        /// </summary>
        /// <param name="name">Specifies the configuration value name.</param>
        /// <param name="node">Optional node path under Certification Authority active node.</param>
        /// <param name="value">
        /// A value to write. Value type must be of <see cref="String"/>, <see cref="Boolean"/>, <see cref="Int32"/>,
        /// <see cref="IEnumerable{String}"/> or <see cref="IEnumerable{Byte}"/>. Any other type will throw <see cref="ArgumentException"/>.
        /// </param>
        /// <exception cref="ArgumentNullException"><strong>value</strong> parameter is null.</exception>
        public RegConfigEntry(String name, String node, Object value) : this(name, value) {
            Node = node;
        }
        /// <summary>
        /// Initializes a new instance of <strong>RegConfigEntry</strong> class using value name, optional node path and value to write.
        /// </summary>
        /// <param name="name">Specifies the configuration value name.</param>
        /// <param name="value">
        /// A value to write. Value type must be of <see cref="String"/>, <see cref="Boolean"/>, <see cref="Int32"/>,
        /// <see cref="IEnumerable{String}"/> or <see cref="IEnumerable{Byte}"/>. Any other type will throw <see cref="ArgumentException"/>.
        /// </param>
        /// <exception cref="ArgumentNullException"><strong>value</strong> parameter is null.</exception>
        public RegConfigEntry(String name, Object value) {
            if (String.IsNullOrWhiteSpace(name)) {
                throw new ArgumentException("Value name cannot be null or empty string.");
            }

            Name = name;
            Action = RegConfigEntryAction.Write;
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets the configuration value name.
        /// </summary>
        public String Name { get; }
        /// <summary>
        /// Gets an optional node path under Certification Authority active node.
        /// </summary>
        public String Node { get; }
        /// <summary>
        /// Gets or sets the value whether root configuration node is used instead of current active configuration node.
        /// </summary>
        public Boolean IsRoot { get; set; }
        /// <summary>
        ///  Gets or sets the configuration value commit action.
        /// </summary>
        public RegConfigEntryAction Action { get; set; }
        /// <summary>
        /// Gets the value to write.
        /// </summary>
        public Object Value { get; }
    }

    /// <summary>
    /// Contains write action upon committing entry back to configuration.
    /// </summary>
    public enum RegConfigEntryAction {
        /// <summary>
        /// Configuration value is updated or created.
        /// </summary>
        Write,
        /// <summary>
        /// Configuration value is deleted.
        /// </summary>
        Delete
    }
}