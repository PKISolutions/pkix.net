using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Utils;
static class GenericArray {
    public static Boolean OidContains(Oid[] source, Oid oid) {
        if (source.Length == 0) { return false; }
        foreach (Oid item in source) {
            if (String.IsNullOrEmpty(oid.FriendlyName)) {
                if (item.Value == oid.Value) { return true; }
            } else {
                if (item.FriendlyName == oid.FriendlyName) { return true; }
            }
        }
        return false;
    }
    public static void RemoveOid(List<Oid> source, Oid oid) {
        for (Int32 index = 0; index < source.Count; index++) {
            if (String.IsNullOrEmpty(oid.FriendlyName)) {
                if (source[index].Value == oid.Value) { source.RemoveAt(index); index--; }
            } else {
                if (source[index].FriendlyName == oid.FriendlyName) { source.RemoveAt(index); index--; }
            }
        }
    }
    public static Boolean RemoveExtension(IList<X509Extension> extensions, String oid) {
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