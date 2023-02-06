using System;

namespace SysadminsLV.PKI.Cryptography;

public static class AlgorithmOid {
    // public key group
    public const String RSA             = "1.2.840.113549.1.1.1";
    public const String DSA             = "1.2.840.10040.4.1";
    public const String ECC             = "1.2.840.10045.2.1";
    // md2 group
    public const String MD2             = "1.2.840.113549.2.2";
    // md4 group
    public const String MD4             = "1.2.840.113549.2.4";
    // md5 group
    public const String MD5             = "1.2.840.113549.2.5";
    public const String MD5_RSA         = "1.2.840.113549.1.1.4";
    // sha1 group
    public const String SHA1            = "1.3.14.3.2.26";
    public const String SHA1_RSA        = "1.2.840.113549.1.1.5";
    public const String SHA1_DSA        = "1.2.840.10040.4.3";
    public const String SHA1_ECDSA      = "1.2.840.10045.4.1";
    // sha256 group
    public const String SHA256          = "2.16.840.1.101.3.4.2.1";
    public const String SHA256_RSA      = "1.2.840.113549.1.1.11";
    public const String SHA256_ECDSA    = "1.2.840.10045.4.3.2";
    // sha384 group
    public const String SHA384          = "2.16.840.1.101.3.4.2.2";
    public const String SHA384_RSA      = "1.2.840.113549.1.1.12";
    public const String SHA384_ECDSA    = "1.2.840.10045.4.3.3";
    // sha 512 group
    public const String SHA512          = "2.16.840.1.101.3.4.2.3";
    public const String SHA512_RSA      = "1.2.840.113549.1.1.13";
    public const String SHA512_ECDSA    = "1.2.840.10045.4.3.4";
    // specified group
    public const String Mgf1            = "1.2.840.113549.1.1.8";
    public const String RSA_PSS         = "1.2.840.113549.1.1.10";
    public const String ECDSA_SPECIFIED = "1.2.840.10045.4.3";

    // ECC named curves
    public const String SecP160R1       = "1.3.132.0.8";
    public const String SecP160K1       = "1.3.132.0.9";
    public const String SecP256K1       = "1.3.132.0.10";
    public const String SecP160R2       = "1.3.132.0.30";
    public const String SecP192K1       = "1.3.132.0.31";
    public const String SecP224K1       = "1.3.132.0.32";
    public const String NistP224        = "1.3.132.0.33";
    public const String ECDSA_P384      = "1.3.132.0.34";
    public const String ECDSA_P521      = "1.3.132.0.35";
    public const String ECDSA_P256      = "1.2.840.10045.3.1.7";

    // ecdsa
    // ecdsa
    public const String ECDSA_PRIME1    = "1.2.840.10045.1.1";
    public const String ECDSA_CHAR2     = "1.2.840.10045.1.2";

    // symmetric alg group
    public const String RC2             = "1.2.840.113549.3.2";
    public const String RC4             = "1.2.840.113549.3.4";
    public const String DES             = "1.3.14.3.2.7";
    public const String TrippleDES      = "1.2.840.113549.3.7";
    public const String AES128          = "2.16.840.1.101.3.4.1.2";
    public const String AES192          = "2.16.840.1.101.3.4.1.22";
    public const String AES256          = "2.16.840.1.101.3.4.1.42";
}
