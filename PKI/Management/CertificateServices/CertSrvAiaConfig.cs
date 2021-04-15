using System;
using System.Collections;
using System.Collections.Generic;
using SysadminsLV.PKI.Management.CertificateServices;

namespace PKI.Management.CertificateServices {
    public class CertSrvAiaConfig : CertSrvConfig, IEnumerable<CertSrvAiaUrlEntry> {
        readonly List<CertSrvAiaUrlEntry> _entries = new List<CertSrvAiaUrlEntry>();

        public CertSrvAiaConfig(String computerName) : base(computerName) {
            ConfigManager.SetRootNode(true);
            initialize();
        }

        void initialize() {
            String[] cdpEntry = ConfigManager.GetMultiStringEntry(ACTIVE_CACERTPUBLICATIONURLS);
            foreach (String regEntry in cdpEntry) {
                _entries.Add(CertSrvAiaUrlEntry.FromRegUri(regEntry));
            }
        }
        public IEnumerator<CertSrvAiaUrlEntry> GetEnumerator() {
            return _entries.GetEnumerator();
        }
        IEnumerator IEnumerable.GetEnumerator() {
            return GetEnumerator();
        }
        public void Add(CertSrvAiaUrlEntry item) {
            if (item == null) {
                throw new ArgumentNullException(nameof(item));
            }

            _entries.Add(item);
            IsModified = true;
        }
        public Boolean Remove(CertSrvAiaUrlEntry item) {
            if (item == null) {
                throw new ArgumentNullException(nameof(item));
            }

            Boolean result = _entries.Remove(item);

            if (result) {
                IsModified = true;
            }

            return result;
        }
        public void Clear() {
            _entries.Clear();
            IsModified = true;
        }

        public Boolean Contains(CertSrvAiaUrlEntry item) {
            return _entries.Contains(item);
        }
        public void CopyTo(CertSrvAiaUrlEntry[] array, Int32 arrayIndex) {
            _entries.CopyTo(array, arrayIndex);
        }

        public Int32 Count => _entries.Count;
        public CertSrvAiaUrlEntry this[Int32 index] => _entries[index];
    }
}
