using System;
using System.Text.RegularExpressions;

namespace SysadminsLV.PKI.Utils;
class Wildcard : Regex {
    //internal Wildcard(String pattern) { }
    public Wildcard(String pattern) : base(WildcardToRegex(pattern)) { }
    public Wildcard(String pattern, RegexOptions options) : base(WildcardToRegex(pattern), options) { }
    public static String WildcardToRegex(String pattern) {
        return "^" + Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
    }
}