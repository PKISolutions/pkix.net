using System;
using System.Management;

namespace SysadminsLV.PKI.Utils;
static class WmiHelper {
    public static ManagementObjectCollection GetWmi(String query, String computerName = ".", String Namespace = "\\root\\CIMv2") {
        if (query == null) {
            throw new ArgumentNullException(nameof(query));
        }
        var oQuery = new ObjectQuery(query);
        var connection = new ConnectionOptions();
        var scope = new ManagementScope(@"\\" + computerName + Namespace, connection);
        scope.Connect();
        var searcher = new ManagementObjectSearcher(scope, oQuery);

        return searcher.Get();
    }
}
