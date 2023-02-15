using System;
using System.Management;

namespace PKI.Utils {
	static class WMI {
		public static ManagementObjectCollection GetWmi(String query, String computerName = ".", String Namespace = "\\root\\CIMv2") {
			if (query == null) {
				throw new ArgumentNullException(nameof(query));
			}
			ObjectQuery oQuery = new ObjectQuery(query);
			ConnectionOptions connection = new ConnectionOptions();
			ManagementScope scope = new ManagementScope(@"\\" + computerName + Namespace, connection);
			scope.Connect();
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, oQuery);
			return searcher.Get();
		}
	}
}
