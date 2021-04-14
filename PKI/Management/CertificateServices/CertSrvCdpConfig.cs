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
                _entries.Add(new CertSrvCdpUrlEntry(regEntry));
            }
        }
        public IEnumerator<CertSrvCdpUrlEntry> GetEnumerator() {
            return _entries.GetEnumerator();
        }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
        public void Add(CertSrvCdpUrlEntry item) {
            throw new NotImplementedException();
        }
        public void Clear() {
            _entries.Clear();
        }
        public Boolean Contains(CertSrvCdpUrlEntry item) {
            throw new NotImplementedException();
        }
        public void CopyTo(CertSrvCdpUrlEntry[] array, Int32 arrayIndex) {
            _entries.CopyTo(array, arrayIndex);
        }
        public Boolean Remove(CertSrvCdpUrlEntry item) {
            throw new NotImplementedException();
        }
        public Int32 Count => _entries.Count;
        public Boolean IsReadOnly => false;
        public CertSrvCdpUrlEntry this[Int32 index] {
            get => _entries[index];
        }
    }
}