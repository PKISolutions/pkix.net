using System;
using System.Net;

namespace PKI.Utils {
	static class Networking {
		static Boolean InSameSubnet(String firstIP, String subNet, String secondIP) {
			UInt32 subnetmaskInInt = ConvertIPToUint(subNet);
			UInt32 firstIPInInt = ConvertIPToUint(firstIP);
			UInt32 secondIPInInt = ConvertIPToUint(secondIP);
			UInt32 networkPortionofFirstIP = firstIPInInt & subnetmaskInInt;
			UInt32 networkPortionofSecondIP = secondIPInInt & subnetmaskInInt;
			return networkPortionofFirstIP == networkPortionofSecondIP;
		}
		static UInt32 ConvertIPToUint(String ipAddress) {
			IPAddress iPAddress = IPAddress.Parse(ipAddress);
			Byte[] byteIP = iPAddress.GetAddressBytes();
			UInt32 ipInUint = (UInt32)byteIP[3] << 24;
			ipInUint += (UInt32)byteIP[2] << 16;
			ipInUint += (UInt32)byteIP[1] << 8;
			ipInUint += byteIP[0];
			return ipInUint;
		}
		public static Boolean InSameSubnet(String firstIP, Int32 subNet, String secondIP) {
			Int64 temp = Convert.ToUInt32(new String('1', subNet).PadRight(32, '0'), 2);
			String[] tokens = new IPAddress(temp).ToString().Split('.');
			Array.Reverse(tokens);
			String subnet = String.Join(".", tokens);
			return InSameSubnet(firstIP, subnet, secondIP);
		}
	}
}
