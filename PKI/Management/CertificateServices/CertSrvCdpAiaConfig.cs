using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using SysadminsLV.PKI.Management.CertificateServices;

namespace PKI.Management.CertificateServices {
    /// <summary>
    /// Represents an abstraction class for ADCS CRL Distribution Point and Authority Information Access
    /// configuration entries.
    /// </summary>
    /// <typeparam name="T">The type of CDP/AIA URL implementation.</typeparam>
    public abstract class CertSrvCdpAiaConfig<T> : CertSrvConfig, ICollection<T> where T : class, ICertSrvCdpAiaUri {
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
            Entries = new List<T>();
        }

        /// <summary>
        /// Gets the element at the specified index.
        /// </summary>
        /// <param name="index">The zero-based index of the element to get or set.</param>
        public T this[Int32 index] => Entries[index];
        /// <summary>
        /// Gets a collection of URI entries.
        /// </summary>
        protected List<T> Entries { get; }

        void modify() {
            ConfigEntries.Clear();
            var entry = new RegConfigEntry(_propertyName, Entries.Select(x => x.GetRegUri()).ToArray()) {
                Action = RegConfigEntryAction.Write
            };
            ConfigEntries.Add(entry);
            IsModified = true;
        }

        /// <inheritdoc />
        public IEnumerator<T> GetEnumerator() {
            return Entries.GetEnumerator();
        }
        IEnumerator IEnumerable.GetEnumerator() {
            return GetEnumerator();
        }
        /// <inheritdoc />
        public void Add(T item) {
            if (item == null) {
                throw new ArgumentNullException(nameof(item));
            }

            Entries.Add(item);
            modify();
        }
        /// <inheritdoc />
        public Boolean Remove(T item) {
            if (item == null) {
                throw new ArgumentNullException(nameof(item));
            }

            Boolean result = Entries.Remove(item);
            if (result) {
                modify();
            }

            return result;
        }
        /// <inheritdoc />
        public void Clear() {
            Entries.Clear();
            modify();
        }

        /// <inheritdoc />
        public Boolean Contains(T item) {
            return Entries.Contains(item);
        }
        /// <inheritdoc />
        public void CopyTo(T[] array, Int32 arrayIndex) {
            Entries.CopyTo(array, arrayIndex);
        }

        /// <inheritdoc />
        public Int32 Count => Entries.Count;
        /// <inheritdoc />
        public Boolean IsReadOnly => false;
    }
}