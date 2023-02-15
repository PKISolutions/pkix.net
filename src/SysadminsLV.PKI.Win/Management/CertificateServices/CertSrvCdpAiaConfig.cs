using System;
using System.Collections.Generic;
using System.Linq;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents an abstraction class for ADCS CRL Distribution Point and Authority Information Access
    /// configuration entries.
    /// </summary>
    /// <typeparam name="T">The type of CDP/AIA URL implementation.</typeparam>
    public abstract class CertSrvCdpAiaConfig<T> : CertSrvConfig where T : ICertSrvCdpAiaUri {
        readonly String _propertyName;

        /// <summary>
        /// Initializes a new instance of <strong>CertSrvCdpAiaConfig</strong> from computer name and configuration
        /// property name.
        /// </summary>
        /// <param name="computerName">Specifies the CA computer name.</param>
        /// <param name="propertyName">Specifies the configuration property name. Must be <i></i></param>
        protected CertSrvCdpAiaConfig(String computerName, String propertyName) : base(computerName) {
            _propertyName = propertyName;
            ConfigManager.SetRootNode(true);
            InternalEntries = new List<T>();
        }

        /// <summary>
        /// Gets the element at the specified index.
        /// </summary>
        /// <param name="index">The zero-based index of the element to get or set.</param>
        public T this[Int32 index] => InternalEntries[index];
        /// <summary>
        /// Gets a writable collection of URI entries.
        /// </summary>
        protected List<T> InternalEntries { get; }

        void modify() {
            ConfigEntries.Clear();
            var entry = new RegConfigEntry(_propertyName, InternalEntries.Select(x => x.GetRegUri()).ToArray()) {
                Action = RegConfigEntryAction.Write
            };
            ConfigEntries.Add(entry);
            IsModified = true;
        }

        /// <inheritdoc cref="List{T}.Add"/>
        public void Add(T item) {
            if (item == null) {
                throw new ArgumentNullException(nameof(item));
            }

            InternalEntries.Add(item);
            modify();
        }
        /// <inheritdoc cref="List{T}.Remove"/>
        public Boolean Remove(T item) {
            if (item == null) {
                throw new ArgumentNullException(nameof(item));
            }

            Boolean result = InternalEntries.Remove(item);
            if (result) {
                modify();
            }

            return result;
        }
        /// <inheritdoc cref="List{T}.Clear"/>
        public void Clear() {
            InternalEntries.Clear();
            modify();
        }
        /// <inheritdoc cref="List{T}.Contains"/>
        public Boolean Contains(T item) {
            return InternalEntries.Contains(item);
        }
        /// <inheritdoc cref="List{T}.CopyTo(T[], Int32)"/>
        public void CopyTo(T[] array, Int32 arrayIndex) {
            InternalEntries.CopyTo(array, arrayIndex);
        }
        /// <inheritdoc cref="List{T}.Count"/>
        public Int32 Count => InternalEntries.Count;
    }
}