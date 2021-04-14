using System;
using System.Collections;
using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices {
    public class CertSrvCdpConfig : CertSrvConfig, IEnumerable<CertSrvCdpUrlEntry> {
        readonly List<CertSrvCdpUrlEntry> _entries = new List<CertSrvCdpUrlEntry>();

        public CertSrvCdpConfig(String computerName) : base(computerName) {
            ConfigManager.SetRootNode(true);
            initialize();
        }

        void initialize() {
            String[] cdpEntry = ConfigManager.GetMultiStringEntry(ACTIVE_CRLPUBLICATIONURLS);
            foreach (String regEntry in cdpEntry) {
                _entries.Add(CertSrvCdpUrlEntry.FromRegUri(regEntry));
            }
        }
        public IEnumerator<CertSrvCdpUrlEntry> GetEnumerator() {
            return _entries.GetEnumerator();
        }
        IEnumerator IEnumerable.GetEnumerator() {
            return GetEnumerator();
        }
        public void Add(CertSrvCdpUrlEntry item) {
            if (item == null) {
                throw new ArgumentNullException(nameof(item));
            }

            _entries.Add(item);
            IsModified = true;
        }
        public Boolean Remove(CertSrvCdpUrlEntry item) {
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

        public Boolean Contains(CertSrvCdpUrlEntry item) {
            return _entries.Contains(item);
        }
        public void CopyTo(CertSrvCdpUrlEntry[] array, Int32 arrayIndex) {
            _entries.CopyTo(array, arrayIndex);
        }
        
        public Int32 Count => _entries.Count;
        public CertSrvCdpUrlEntry this[Int32 index] => _entries[index];
    }
}