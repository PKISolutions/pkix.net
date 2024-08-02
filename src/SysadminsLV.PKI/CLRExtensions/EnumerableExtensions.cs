using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.CLRExtensions;
static class EnumerableExtensions {
    public static Boolean RemoveExtension(this IList<X509Extension> extensions, String oid) {
        Int32 index = -1;
        for (Int32 i = 0; i < extensions.Count; i++) {
            if (extensions[i].Oid.Value.Equals(oid)) {
                index = i;
                break;
            }
        }

        if (index == -1) { return false; }
        extensions.RemoveAt(index);
        return true;
    }
}
