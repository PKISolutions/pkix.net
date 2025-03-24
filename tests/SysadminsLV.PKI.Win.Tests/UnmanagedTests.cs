using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PKI.Structs;
using SysadminsLV.PKI.Structs;

namespace SysadminsLV.PKI.Win.Tests;

[TestClass]
public class UnmanagedTests {
    [TestMethod]
    public void TestCryptoApiBlob() {
        Byte[] buffer = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        var blob = Wincrypt.CRYPTOAPI_BLOB.FromBinaryData(buffer);
        Assert.AreEqual(buffer.Length, (Int32)blob.cbData);
        Assert.IsFalse(IntPtr.Zero.Equals(blob.pbData));

        SafeCryptoApiBlobContext blobPtr = blob.GetSafeContext();
        Assert.IsFalse(IntPtr.Zero.Equals(blobPtr.DangerousGetHandle()));
        Assert.IsFalse(blobPtr.IsInvalid);
        Assert.IsFalse(blobPtr.IsClosed);

        blob.Dispose();
        Assert.AreEqual(0, (Int32)blob.cbData);
        Assert.IsTrue(IntPtr.Zero.Equals(blob.pbData));
        // test idempotency. Should not fail
        blob.Dispose();

        blobPtr.Dispose();
        Assert.IsTrue(blobPtr.IsInvalid);
        Assert.IsTrue(blobPtr.IsClosed);
        // test idempotency. Should not fail
        blobPtr.Dispose();
    }
}
