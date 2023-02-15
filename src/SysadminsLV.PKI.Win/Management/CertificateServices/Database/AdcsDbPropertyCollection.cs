using System;
using System.Collections;
using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices.Database {
    /// <summary>
    /// Contains a collection of ADCS database entry properties.
    /// </summary>
    public class AdcsDbPropertyCollection : IDictionary<String, Object> {
        readonly IDictionary<String, Object> _dictionary = new Dictionary<String, Object>(StringComparer.InvariantCultureIgnoreCase);
        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>An enumerator that can be used to iterate through the collection.</returns>
        public IEnumerator<KeyValuePair<String, Object>> GetEnumerator() {
            return _dictionary.GetEnumerator();
        }
        /// <inheritdoc />
        IEnumerator IEnumerable.GetEnumerator() {
            return GetEnumerator();
        }
        /// <summary>
        /// Adds an item to the dictionary.
        /// </summary>
        /// <param name="item">The object to add to the dictionary.</param>
        public void Add(KeyValuePair<String, Object> item) {
            _dictionary.Add(item);
        }
        /// <summary>
        /// Removes all items from the dictionary.
        /// </summary>
        public void Clear() {
            _dictionary.Clear();
        }
        /// <summary>
        /// Determines whether the dictionary contains a specific value.
        /// </summary>
        /// <param name="item">The object to locate in the dictionary.</param>
        /// <returns><strong>True</strong> if item is found in the dictionary; otherwise, <strong>False</strong>.</returns>
        public Boolean Contains(KeyValuePair<String, Object> item) {
            return _dictionary.Contains(item);
        }
        /// <summary>
        /// Copies the elements of the dictionary to an <see cref="Array"/>, starting at a particular
        /// <see cref="Array"/> index.
        /// </summary>
        /// <param name="array">
        /// The one-dimensional <see cref="Array"/> that is the destination of the elements copied from dictionary.
        /// The <see cref="Array"/> must have zero-based indexing.
        /// </param>
        /// <param name="arrayIndex">The zero-based index in array at which copying begins.</param>
        public void CopyTo(KeyValuePair<String, Object>[] array, Int32 arrayIndex) {
            _dictionary.CopyTo(array, arrayIndex);
        }
        /// <summary>
        /// Removes the first occurrence of a specific object from the dictionary.
        /// </summary>
        /// <param name="item">The object to remove from the dictionary.</param>
        /// <returns>
        /// <strong>True</strong> if item was successfully removed from the dictionary; otherwise,
        /// <strong>False</strong>. This method also returns false if item is not found in the original
        /// dictionary.
        /// </returns>
        public Boolean Remove(KeyValuePair<String, Object> item) {
            return _dictionary.Remove(item);
        }
        /// <summary>
        /// Gets the number of elements contained in the dictionary.
        /// </summary>
        public Int32 Count => _dictionary.Count;
        /// <summary>
        /// Gets a value indicating whether the dictionary is read-only.
        /// </summary>
        /// <remarks>This member always returns <strong>False</strong>.</remarks>
        public Boolean IsReadOnly => _dictionary.IsReadOnly;
        /// <summary>
        /// Determines whether the dictionary contains the specified key.
        /// </summary>
        /// <param name="key">The key to locate in the dictionry.</param>
        /// <returns>
        /// <strong>True</strong> if the dictionary contains an element with the specified key;
        /// otherwise, <strong>False</strong>.
        /// </returns>
        public Boolean ContainsKey(String key) {
            return _dictionary.ContainsKey(key);
        }
        /// <summary>
        /// Adds the specified key and value to the dictionary.
        /// </summary>
        /// <param name="key">The key of the element to add.</param>
        /// <param name="value">The value of the element to add. The value can be null for reference types.</param>
        public void Add(String key, Object value) {
            _dictionary.Add(key, value);
        }
        /// <summary>
        /// Removes the value with the specified key from the dictionary.
        /// </summary>
        /// <param name="key">The key of the element to remove.</param>
        /// <returns>
        /// <strong>True</strong> if item was successfully removed from the dictionary; otherwise,
        /// <strong>False</strong>. This method also returns false if item is not found in the original
        /// dictionary.
        /// </returns>
        public Boolean Remove(String key) {
            return _dictionary.Remove(key);
        }
        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        /// <param name="key">The key of the value to get.</param>
        /// <param name="value">
        /// When this method returns, contains the value associated with the specified key, if the key is found;
        /// otherwise, the default value for the type of the value parameter. This parameter is passed uninitialized.
        /// </param>
        /// <returns>
        /// <strong>True</strong> if the dictionary contains an element with the specified key;
        /// otherwise, <strong>False</strong>.
        /// </returns>
        public Boolean TryGetValue(String key, out Object value) {
            return _dictionary.TryGetValue(key, out value);
        }
        /// <summary>
        /// Gets or sets the value associated with the specified key.
        /// </summary>
        /// <param name="key">The key of the value to get or set.</param>
        /// <returns>The value associated with the specified key. If the specified key is not found, a get
        /// operation throws a <see cref="KeyNotFoundException"/>, and a set operation creates a new element
        /// with the specified key.</returns>
        public Object this[String key] {
            get => _dictionary[key];
            set => _dictionary[key] = value;
        }
        /// <summary>
        /// Gets a collection containing the keys in the dictionary.
        /// </summary>
        public ICollection<String> Keys => _dictionary.Keys;
        /// <summary>
        /// Gets a collection containing the values in the dictionary.
        /// </summary>
        public ICollection<Object> Values => _dictionary.Values;
    }
}