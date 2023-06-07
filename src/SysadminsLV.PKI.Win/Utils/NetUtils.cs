using System;
using System.Net;

namespace SysadminsLV.PKI.Utils;

static class NetUtils {
    static Boolean inSameSubnet(String firstIP, String subNet, String secondIP) {
        UInt32 subnetMaskAsInt = convertIPToUint(subNet);
        UInt32 firstIPInInt = convertIPToUint(firstIP);
        UInt32 secondIPInInt = convertIPToUint(secondIP);
        UInt32 networkPortionOfFirstIP = firstIPInInt & subnetMaskAsInt;
        UInt32 networkPortionOfSecondIP = secondIPInInt & subnetMaskAsInt;
        return networkPortionOfFirstIP == networkPortionOfSecondIP;
    }
    static UInt32 convertIPToUint(String ipAddress) {
        var iPAddress = IPAddress.Parse(ipAddress);
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
        return inSameSubnet(firstIP, subnet, secondIP);
    }
}