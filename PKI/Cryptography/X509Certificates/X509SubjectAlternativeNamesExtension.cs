using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    ///		<strong>X509SubjectAlternativeNamesExtension</strong> represents a X.509 alternative names extension.
    ///		The subject alternative name extension allows identities to be bound to the subject of the certificate.
    ///		These identities may be included in addition to or in place of the identity in the subject field of
    ///		the certificate.
    /// </summary>
    public sealed class X509SubjectAlternativeNamesExtension : X509Extension {
        readonly Oid _oid = new(X509ExtensionOid.SubjectAlternativeNames);
        X509AlternativeNameCollection alternativeNames = new();

        internal X509SubjectAlternativeNamesExtension(Byte[] rawData, Boolean critical)
            : base(X509ExtensionOid.SubjectAlternativeNames, rawData, critical) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            m_decode(rawData);
        }

        /// <summary>
        ///		Initializes a new instance of the <strong>X509SubjectAlternativeNamesExtension</strong> class using an
        ///		<see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="altNames">The encoded data to use to create the extension.</param>
        /// <param name="critical">
        ///		<strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
        /// </param>
        public X509SubjectAlternativeNamesExtension(AsnEncodedData altNames, Boolean critical) : this(altNames.RawData, critical) { }
        /// <summary>
        ///		Initializes a new instance of the <strong>X509SubjectAlternativeNamesExtension</strong> class using a
        ///		collection of alternative names and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="altNames">A collection of alternative name objects.</param>
        /// <param name="critical">
        ///		<strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
        /// </param>
        public X509SubjectAlternativeNamesExtension(X509AlternativeNameCollection altNames, Boolean critical) {
            if (altNames.Count == 0) { throw new ArgumentException("Empty arrays are not supported."); }
            m_initizlize(altNames, critical);
        }
        
        /// <summary>
        /// Gets an array of alternative names.
        /// </summary>
        public X509AlternativeNameCollection AlternativeNames {
            get {
                X509AlternativeNameCollection retValue = new X509AlternativeNameCollection();
                foreach (X509AlternativeName altName in alternativeNames) {
                    retValue.Add(altName);
                }
                return retValue;
            }
        }

        void m_initizlize(X509AlternativeNameCollection altNames, Boolean critical) {
            foreach (X509AlternativeName altName in altNames) {
                if (String.IsNullOrEmpty(altName.Value)) {
                    throw new ArgumentException($"Empty value for {altName.Type} is not allowed.");
                }
            }
            Critical = critical;
            Oid = _oid;
            RawData = altNames.Encode();
            alternativeNames = altNames;
        }
        void m_decode(Byte[] rawData) {
            alternativeNames.Decode(rawData);
            foreach (X509AlternativeName altName in alternativeNames) {
                if (String.IsNullOrEmpty(altName.Value)) {
                    throw new ArgumentException($"Empty value for {altName.Type} is not allowed.");
                }
            }
        }
    }
}
