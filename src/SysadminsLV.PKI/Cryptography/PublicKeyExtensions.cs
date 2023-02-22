using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Contains extension methods for <see cref="PublicKey"/> class.
/// </summary>
public static class PublicKeyExtensions {
    public static PublicKey FromRawData(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        var asn = new Asn1Reader(rawData);
        asn.MoveNext();
        var pubKeyOidIdReader = new Asn1Reader(asn.GetTagRawData());
        pubKeyOidIdReader.MoveNext();
        Oid pubKeyOid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
        pubKeyOidIdReader.MoveNext();
        var encodedParams = new AsnEncodedData(pubKeyOid, pubKeyOidIdReader.GetTagRawData());
        asn.MoveNextSibling();
        var encodedKey = new AsnEncodedData(pubKeyOid, new Asn1BitString(asn.GetTagRawData()).Value.ToArray());
        
        return new PublicKey(pubKeyOid, encodedParams, encodedKey);
    }
    /// <summary>
    /// Gets a managed implementation of public key instance.
    /// </summary>
    /// <param name="publicKey"></param>
    /// <returns>An instance of <see cref="AsymmetricKeyPair"/>.</returns>
    /// <exception cref="ArgumentException"></exception>
    public static AsymmetricKeyPair GetAsymmetricKeyPair(this PublicKey publicKey) {
        switch (publicKey.Oid.Value) {
            case AlgorithmOid.DSA:
                return new DsaPublicKey(publicKey);
            case AlgorithmOid.ECC:
                return new ECDsaPublicKey(publicKey);
            case AlgorithmOid.RSA:
                return new RsaPublicKey(publicKey);
            default:
                throw new ArgumentException($"Asymmetric algorithm '{publicKey.Oid.Value}' is not supported.");
        }
    }
    public static Boolean VerifySignature(this PublicKey pubKey, SignedContentBlob signedBlob) {
        return CryptSigner.VerifyData(signedBlob, pubKey);
    }
    /// <summary>
    /// Encodes public key to a ASN.1 compatible format that includes key algorithm, key algorithm parameters
    /// and encoded key value.
    /// </summary>
    /// <param name="publicKey"></param>
    /// <returns>ASN.1 encoded byte array.</returns>
    public static Byte[] Encode(this PublicKey publicKey) {
        var rawData = new List<Byte>();
        rawData.AddRange(new Asn1ObjectIdentifier(publicKey.Oid.Value).GetRawData());
        rawData.AddRange(publicKey.EncodedParameters.RawData);
        rawData.InsertRange(0, Asn1Utils.GetLengthBytes(rawData.Count));
        rawData.Insert(0, 48);
        rawData.AddRange(new Asn1BitString(publicKey.EncodedKeyValue.RawData, false).GetRawData());
        return Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    public static String Format(this PublicKey publicKey) {
        var sb = new StringBuilder();
        String keyParamsString;
        switch (publicKey.Oid.Value) {
            case AlgorithmOid.ECC:
                keyParamsString = AsnFormatter
                    .BinaryToString(publicKey.EncodedParameters.RawData, EncodingType.HexAddress)
                    .TrimEnd();
                keyParamsString += $"\r\n        {new Asn1ObjectIdentifier(publicKey.EncodedParameters.RawData).Value.Format(true)}";
                break;
            case AlgorithmOid.RSA:
                keyParamsString = AsnFormatter.BinaryToString(new Asn1Null().GetRawData(), EncodingType.Hex);
                break;
            default:
                keyParamsString = AsnFormatter
                    .BinaryToString(publicKey.EncodedParameters.RawData, EncodingType.HexAddress)
                    .Replace("\r\n", "\r\n    ")
                    .TrimEnd();
                break;
        }
        String keyValueString = AsnFormatter
            .BinaryToString(publicKey.EncodedKeyValue.RawData, EncodingType.HexAddress)
            .Replace("\r\n", "\r\n    ")
            .TrimEnd();
        sb.Append(
            $@"Public Key Algorithm:
    Algorithm ObjectId: {publicKey.Oid.FriendlyName} ({publicKey.Oid.Value})
    Algorithm Parameters:
    {keyParamsString.TrimEnd()}
Public Key Length: {publicKey.GetKeyLength()} bits
Public Key: UnusedBits = 0
    {keyValueString}
");
        return sb.ToString();
    }
    public static Int32 GetKeyLength(this PublicKey publicKey) {
        if (publicKey == null) {
            throw new ArgumentNullException(nameof(publicKey));
        }

        switch (publicKey.Oid.Value) {
            case AlgorithmOid.RSA:
            case AlgorithmOid.DSA:
            case AlgorithmOid.ECC:
                return publicKey.Key.KeySize;
            default:
                return 0;

        }
    }

    // all magic numbers are for public keys only.
    const Int32 RSA_MAGIC = 0x31415352;
    const Int32 DSA_V1_MAGIC = 0x42505344; // 512-1024 bit, legacy
    const Int32 DSA_V2_MAGIC = 0x32425044; // up to 3072, CNG, starts with Win8
    const Int32 ECDSA_P256_MAGIC = 0x31534345;
    const Int32 ECDSA_P384_MAGIC = 0x33534345;
    const Int32 ECDSA_P521_MAGIC = 0x35534345;
    public static Byte[] GetCryptBlob(this PublicKey publicKey) {
        var blob = new List<Byte>();
        switch (publicKey.Oid.Value) {
            // RSA
            case AlgorithmOid.RSA:
                readRsaHeader(blob, publicKey);
                break;
            // DSA
            case AlgorithmOid.DSA:
                // DSA has two formats, legacy and new. Legacy DSA keys are up to 1024 bit and support
                // SHA1 hash algorithm only. Larger keys support up to 2048? bit keys and new hashing algorithms,
                // SHA1, SHA256 and SHA512. SHA384 somehow is missing, see bcrypt.h file for
                // HASHALGORITHM_ENUM
                // so check the key size and read appropriate header. Public key length in bits is
                // EncodedPublicKey * 8. Encoded key value includes ASN.1 tag (INTEGER), length (up to
                // two bytes) and extra zero byte if most-significant bit is 1, so 132 bytes max for 1024 key.
                if (publicKey.EncodedKeyValue.RawData.Length <= 132) {
                    readDsaV1Header(blob, publicKey);
                } else {
                    readDsaV2Header(blob, publicKey);
                }
                break;
            // ECC/ECDSA
            case AlgorithmOid.ECC:
                readEcdsaHeader(blob, publicKey);
                break;
            default:
                throw new InvalidOperationException(new Win32Exception(Win32ErrorCode.InvalidParameterException).Message);
        }
        return blob.ToArray();
    }
    static Tuple<Byte[], Byte[]> getRsaComponents(PublicKey publicKey) {
        var asn = new Asn1Reader(publicKey.EncodedKeyValue.RawData);
        asn.MoveNext(); // pub key
        Byte[] modulus = asn.GetPayload();
        // if modulus is negative (usually) it is prepended with extra leading zero in ASN encoding.
        // But this zero is not a part of modulus, so strip it
        if (modulus.Length % 8 > 0) {
            modulus = modulus.Skip(1).ToArray();
        }
        asn.MoveNext(); // exponent
        Byte[] pubExponent = asn.GetPayload();
        return new Tuple<Byte[], Byte[]>(modulus, pubExponent);
    }
    static void readRsaHeader(List<Byte> blob, PublicKey publicKey) {
        /*
        typedef struct _BCRYPT_RSAKEY_BLOB {
          ULONG Magic;          -- 0x31415352
          ULONG BitLength       -- bitLen
          ULONG cbPublicExp;    -- const 3
          ULONG cbModulus;      -- bitLen/8
          ULONG cbPrime1;       -- const 0
          ULONG cbPrime2;       -- const 0
        } BCRYPT_RSAKEY_BLOB; -- public key only
        */
        // Item1 -- modulus
        // Item2 -- public exponent
        Tuple<Byte[], Byte[]> rsaComponents = getRsaComponents(publicKey);
        blob.AddRange(BitConverter.GetBytes(RSA_MAGIC));                        // Magic
        blob.AddRange(BitConverter.GetBytes(rsaComponents.Item1.Length * 8));   // bitLen
        blob.AddRange(BitConverter.GetBytes(rsaComponents.Item2.Length));       // cbPublicExp
        blob.AddRange(BitConverter.GetBytes(rsaComponents.Item1.Length));       // cbModulus
        blob.AddRange(BitConverter.GetBytes(0));                                // cbPrime1
        blob.AddRange(BitConverter.GetBytes(0));                                // cbPrime2
        /*
        BCRYPT_RSAKEY_BLOB
        PublicExponent[cbPublicExp] // Big-endian.
        Modulus[cbModulus] // Big-endian.
         */
        blob.AddRange(rsaComponents.Item2);
        blob.AddRange(rsaComponents.Item1);
    }
    static void readDsaV1Header(List<Byte> blob, PublicKey publicKey) {
        /*
        typedef struct _BCRYPT_DSA_KEY_BLOB {
            ULONG dwMagic;
            ULONG cbKey;
            UCHAR Count[4];
            UCHAR Seed[20];
            UCHAR q[20];
        } BCRYPT_DSA_KEY_BLOB, *PBCRYPT_DSA_KEY_BLOB; -- public key only
        */
        blob.AddRange(BitConverter.GetBytes(DSA_V1_MAGIC));
        blob.AddRange(BitConverter.GetBytes(publicKey.Key.KeySize));
        DSAParameters parameters = ((DSACryptoServiceProvider)publicKey.Key).ExportParameters(false);
        if (parameters.Seed == null) {
            // fill count and seed values with 0xff
            for (Int32 index = 0; index < 24; index++) {
                blob.Add(0xff);
            }
        } else {
            // seed is exactly 20 bytes long
            if (parameters.Seed.Length != 20) {
                throw new ArgumentException("Seed parameter is incorrect.");
            }
            blob.AddRange(BitConverter.GetBytes(parameters.Counter));
            blob.AddRange(parameters.Seed);
        }
        blob.AddRange(parameters.Q);
        /*
        BCRYPT_DSA_KEY_BLOB
        Modulus[cbKey]    // Big-endian. Base Generator G, Prime Modulus P, SubPrime Q, Public Key.
        Generator[cbKey]  // Big-endian.
        Public[cbKey]     // Big-endian.
        */
        blob.AddRange(parameters.P);
        blob.AddRange(parameters.G);
        blob.AddRange(parameters.Y);
        blob.Clear();
        // for some reasons, newer structure doesn't work for DSA keys. Until I can figure out
        // new DSA keys (introduced in Windows 8) are not supported.
        blob.AddRange(((DSACryptoServiceProvider)publicKey.Key).ExportCspBlob(false));
    }
    static void readDsaV2Header(List<Byte> blob, PublicKey publicKey) {
        /*
        typedef struct _BCRYPT_DSA_KEY_BLOB_V2 {
            ULONG               dwMagic;
            ULONG               cbKey;
            HASHALGORITHM_ENUM  hashAlgorithm;      -- SHA1 - 0, SHA256 - 1, SHA512 - 2
            DSAFIPSVERSION_ENUM standardVersion;    -- DSA_FIPS186_2 - 0, 
            ULONG               cbSeedLength;
            ULONG               cbGroupSize;
            UCHAR               Count[4];
        } BCRYPT_DSA_KEY_BLOB_V2, *PBCRYPT_DSA_KEY_BLOB_V2;
        according to: https://msdn.microsoft.com/en-us/library/windows/desktop/jj670561(v=vs.85).aspx
        this struct is available only starting with Windows 8/Windows Server 2012
        */
        Version version = Environment.OSVersion.Version;
        if ((version.Major != 6 || version.Minor < 2) && version.Major <= 6) {
            throw new PlatformNotSupportedException("DSAv2 keys are supported on systems started with Windows 8/Windows Server 2012.");
        }
        blob.AddRange(BitConverter.GetBytes(DSA_V2_MAGIC));
        blob.AddRange(BitConverter.GetBytes(publicKey.Key.KeySize));
        DSAParameters parameters = ((DSACryptoServiceProvider)publicKey.Key).ExportParameters(false);
        switch (parameters.Q.Length) {
            case 20:
                blob.AddRange(BitConverter.GetBytes((Int32)BCRYPT_HASHALGORITHM_ENUM.DSA_HASH_ALGORITHM_SHA1));
                break;
            case 32:
                blob.AddRange(BitConverter.GetBytes((Int32)BCRYPT_HASHALGORITHM_ENUM.DSA_HASH_ALGORITHM_SHA256));
                break;
            case 64:
                blob.AddRange(BitConverter.GetBytes((Int32)BCRYPT_HASHALGORITHM_ENUM.DSA_HASH_ALGORITHM_SHA512));
                break;
            default:
                throw new ArgumentException("Q-parameter is invalid");
        }
        blob.AddRange(BitConverter.GetBytes((Int32)BCRYPT_DSAFIPSVERSION_ENUM.DSA_FIPS186_3));
        if (parameters.Seed == null) {
            // fill cbSeedLength with 0xff
            for (Int32 index = 0; index < parameters.Q.Length + 4; index++) {
                blob.Add(0xff);
            }
        } else {
            blob.AddRange(BitConverter.GetBytes(parameters.Seed.Length));
            blob.AddRange(BitConverter.GetBytes(parameters.Q.Length));
            blob.AddRange(BitConverter.GetBytes(parameters.Counter));
            blob.AddRange(parameters.Seed);
        }

        blob.AddRange(parameters.Q);
        /*
        BCRYPT_DSA_KEY_BLOB
        Modulus[cbKey]    // Big-endian.
        Generator[cbKey]  // Big-endian.
        Public[cbKey]     // Big-endian.
        */
        blob.AddRange(parameters.P);
        blob.AddRange(parameters.G);
        blob.AddRange(parameters.Y);
    }
    static void readEcdsaHeader(List<Byte> blob, PublicKey publicKey) {
        /*
        typedef struct _BCRYPT_ECCKEY_BLOB {
          ULONG Magic;
          ULONG cbKey;
        } BBCRYPT_ECCKEY_BLOB, *PBCRYPT_ECCKEY_BLOB; -- public key only
        */
        // headers from bcrypt.h
        switch (new Asn1ObjectIdentifier(publicKey.EncodedParameters.RawData).Value.Value) {
            // P256
            case AlgorithmOid.ECDSA_P256:
                blob.AddRange(BitConverter.GetBytes(ECDSA_P256_MAGIC));
                blob.AddRange(BitConverter.GetBytes(256 / 8));
                break;
            // P384
            case AlgorithmOid.ECDSA_P384:
                blob.AddRange(BitConverter.GetBytes(ECDSA_P384_MAGIC));
                blob.AddRange(BitConverter.GetBytes(384 / 8));
                break;
            // P521
            case AlgorithmOid.ECDSA_P521:
                blob.AddRange(BitConverter.GetBytes(ECDSA_P521_MAGIC));
                blob.AddRange(BitConverter.GetBytes(528 / 8));
                break;
            default:
                throw new CryptographicException("Specified elliptic curve is not supported.");
        }
        // skip first byte, it is always 0X04 for ECDSA public key
        blob.AddRange(publicKey.EncodedKeyValue.RawData.Skip(1));
    }

    enum BCRYPT_HASHALGORITHM_ENUM {
        DSA_HASH_ALGORITHM_SHA1 = 0,
        DSA_HASH_ALGORITHM_SHA256 = 1,
        DSA_HASH_ALGORITHM_SHA512 = 2
    }

    enum BCRYPT_DSAFIPSVERSION_ENUM {
        DSA_FIPS186_2 = 0,
        DSA_FIPS186_3 = 1
    }
}