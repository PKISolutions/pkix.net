using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.CLRExtensions;

namespace SysadminsLV.PKI.Utils.CLRExtensions {
    /// <summary>
    /// Contains extension methods for <see cref="X509ExtensionCollection"/> class.
    /// </summary>
    public static class X509ExtensionCollectionExtensions {
        /// <summary>
        /// Encodes existing collection of <see cref="X509Extension"/> objects to ASN.1-encoded byte array.
        /// </summary>
        /// <param name="extensions">Extension collection to encode.</param>
        /// <param name="enclosingTag">
        /// Outer ASN.1 type. Default is <strong>SEQUENCE</strong>.
        /// </param>
        /// <exception cref="ArgumentNullException"><strong>extensions</strong> parameter is null.</exception>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] Encode(this X509ExtensionCollection extensions, Byte enclosingTag = 48) {
            if (extensions == null) {
                throw new ArgumentNullException(nameof(extensions));
            }

            var rawData = new List<Byte>();
            foreach (X509Extension e in extensions) {
                rawData.AddRange(e.Encode());
            }

            return Asn1Utils.Encode(rawData.ToArray(), enclosingTag);
        }
        /// <summary>
        /// Decodes ASN.1-encoded byte array that represents a collection of <see cref="X509Extension"/> objects.
        /// </summary>
        /// <param name="extensions">Destination collection where decoded extensions will be added.</param>
        /// <param name="rawData">ASN.1-encoded byte array that represents extension collection.</param>
        /// <exception cref="Asn1InvalidTagException">Decoder encountered an unexpected ASN.1 type identifier.</exception>
        /// <exception cref="ArgumentNullException">
        /// <strong>extensions</strong> and/or <strong>rawData</strong> parameter is null.
        /// </exception>
        /// <remarks>If current collection contains items, decoded items will be appended to existing items.</remarks>
        public static void Decode(this X509ExtensionCollection extensions, Byte[] rawData) {
            if (extensions == null) {
                throw new ArgumentNullException(nameof(extensions));
            }
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }

            Decode(extensions, new Asn1Reader(rawData));
        }
        /// <summary>
        /// Decodes ASN.1-encoded byte array that represents a collection of <see cref="X509Extension"/> objects.
        /// </summary>
        /// <param name="extensions">Destination collection where decoded extensions will be added.</param>
        /// <param name="asn">ASN.1 reader which points to the beginning of the extenstion collection structure.</param>
        /// <exception cref="Asn1InvalidTagException">Decoder encountered an unexpected ASN.1 type identifier.</exception>
        /// <exception cref="ArgumentNullException">
        /// <strong>extensions</strong> and/or <strong>asn</strong> parameter is null.
        /// </exception>
        /// <remarks> If current collection contains items, decoded items will be appended to existing items.</remarks>
        public static void Decode(this X509ExtensionCollection extensions, Asn1Reader asn) {
            if (extensions == null) {
                throw new ArgumentNullException(nameof(extensions));
            }
            if (asn == null) {
                throw new ArgumentNullException(nameof(asn));
            }
            Int32 offset = asn.Offset;
            if (!asn.MoveNext() || asn.PayloadLength == 0) {
                return;
            }

            do {
                extensions.Add(X509ExtensionExtensions.Decode(asn));
            } while (asn.MoveNextSibling());
            asn.Seek(offset);
        }
        /// <summary>
        /// Adds a collection of <see cref="X509Extension"/> objects to existing collection.
        /// </summary>
        /// <param name="extensions">Destination collection where items will be added.</param>
        /// <param name="itemsToAdd">A source collection of items to add to destination.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>extensions</strong> and/or <strong>itemsToAdd</strong> is null.
        /// </exception>
        public static void AddRange(this X509ExtensionCollection extensions, IEnumerable<X509Extension> itemsToAdd) {
            if (extensions == null) { throw new ArgumentNullException(nameof(extensions)); }
            if (itemsToAdd == null) { throw new ArgumentNullException(nameof(itemsToAdd)); }
            foreach (X509Extension e in itemsToAdd) {
                extensions.Add(e);
            }
        }
        /// <summary>
        /// Gets formatted text dump of the current extension collection.
        /// </summary>
        /// <param name="extensions">An existing instance of <see cref="X509ExtensionCollection"/> class.</param>
        /// <returns>Multiline text dump.</returns>
        public static String Format(this X509ExtensionCollection extensions) {
            if (extensions == null || extensions.Count == 0) {
                return String.Empty;
            }

            var sb = new StringBuilder();

            foreach (X509Extension extension in extensions) {
                sb.AppendLine($@"    {extension.Oid.Format(true)}, Critial={extension.Critical}, Length={extension.RawData.Length} (0x{extension.RawData.Length:x}):
        {extension.Format(true).Replace("\r\n", "\r\n        ")}");
            }

            return sb.ToString().TrimEnd();
        }
    }
}
