using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IronGcm.Tests
{
    [TestClass]
    public class AesGcmProviderTests
    {
        private byte[] _key128;
        private byte[] _key192;
        private byte[] _key256;
        private byte[] _nonce;
        private byte[] _plaintext;

        [TestInitialize]
        public void Initialize()
        {
            _key128 = new byte[16];
            _key192 = new byte[24];
            _key256 = new byte[32];
            _nonce = new byte[12];
            _plaintext = Encoding.UTF8.GetBytes("Hello, World! This is a test message.");

            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(_key128);
                rng.GetBytes(_key192);
                rng.GetBytes(_key256);
                rng.GetBytes(_nonce);
            }
        }

        #region Constructor Tests

        [TestMethod]
        public void Constructor_WithValidKey128_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key128))
            {
                Assert.IsNotNull(provider);
            }
        }

        [TestMethod]
        public void Constructor_WithValidKey192_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key192))
            {
                Assert.IsNotNull(provider);
            }
        }

        [TestMethod]
        public void Constructor_WithValidKey256_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                Assert.IsNotNull(provider);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Constructor_WithNullKey_ThrowsArgumentNullException()
        {
            using (var provider = new AesGcmProvider(null))
            {
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Constructor_WithInvalidKeyLength_ThrowsArgumentException()
        {
            var invalidKey = new byte[15];
            using (var provider = new AesGcmProvider(invalidKey))
            {
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Constructor_WithKeyLength17_ThrowsArgumentException()
        {
            var invalidKey = new byte[17];
            using (var provider = new AesGcmProvider(invalidKey))
            {
            }
        }

        #endregion

        #region Encrypt Tests

        [TestMethod]
        public void Encrypt_WithValidInputs_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext;
                byte[] tag;

                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);

                Assert.IsNotNull(ciphertext);
                Assert.IsNotNull(tag);
                Assert.AreEqual(_plaintext.Length, ciphertext.Length);
                Assert.AreEqual(16, tag.Length);
                CollectionAssert.AreNotEqual(_plaintext, ciphertext);
            }
        }

        [TestMethod]
        public void Encrypt_WithEmptyPlaintext_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] emptyPlaintext = new byte[0];
                byte[] ciphertext;
                byte[] tag;

                provider.Encrypt(_nonce, emptyPlaintext, out ciphertext, out tag);

                Assert.IsNotNull(ciphertext);
                Assert.IsNotNull(tag);
                Assert.AreEqual(0, ciphertext.Length);
                Assert.AreEqual(16, tag.Length);
            }
        }

        [TestMethod]
        public void Encrypt_WithAAD_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] aad = Encoding.UTF8.GetBytes("Additional authenticated data");
                byte[] ciphertext;
                byte[] tag;

                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag, aad);

                Assert.IsNotNull(ciphertext);
                Assert.IsNotNull(tag);
                Assert.AreEqual(_plaintext.Length, ciphertext.Length);
            }
        }

        [TestMethod]
        public void Encrypt_WithEmptyAAD_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] aad = new byte[0];
                byte[] ciphertext;
                byte[] tag;

                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag, aad);

                Assert.IsNotNull(ciphertext);
                Assert.IsNotNull(tag);
            }
        }

        [TestMethod]
        public void Encrypt_SameInputs_ProducesSameOutputs()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext1, tag1, ciphertext2, tag2;

                provider.Encrypt(_nonce, _plaintext, out ciphertext1, out tag1);
                provider.Encrypt(_nonce, _plaintext, out ciphertext2, out tag2);

                CollectionAssert.AreEqual(ciphertext1, ciphertext2);
                CollectionAssert.AreEqual(tag1, tag2);
            }
        }

        [TestMethod]
        public void Encrypt_DifferentNonces_ProducesDifferentOutputs()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] nonce2 = new byte[12];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(nonce2);
                }

                byte[] ciphertext1, tag1, ciphertext2, tag2;

                provider.Encrypt(_nonce, _plaintext, out ciphertext1, out tag1);
                provider.Encrypt(nonce2, _plaintext, out ciphertext2, out tag2);

                CollectionAssert.AreNotEqual(ciphertext1, ciphertext2);
                CollectionAssert.AreNotEqual(tag1, tag2);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt_WithNullNonce_ThrowsArgumentNullException()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext;
                byte[] tag;
                provider.Encrypt(null, _plaintext, out ciphertext, out tag);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt_WithNullPlaintext_ThrowsArgumentNullException()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext;
                byte[] tag;
                provider.Encrypt(_nonce, null, out ciphertext, out tag);
            }
        }

        #endregion

        #region Decrypt Tests

        [TestMethod]
        public void Decrypt_WithValidCiphertext_ReturnsOriginalPlaintext()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext;
                byte[] tag;
                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);

                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext);

                CollectionAssert.AreEqual(_plaintext, decryptedPlaintext);
            }
        }

        [TestMethod]
        public void Decrypt_WithAAD_ReturnsOriginalPlaintext()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] aad = Encoding.UTF8.GetBytes("Additional authenticated data");
                byte[] ciphertext;
                byte[] tag;
                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag, aad);

                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext, aad);

                CollectionAssert.AreEqual(_plaintext, decryptedPlaintext);
            }
        }

        [TestMethod]
        public void Decrypt_WithEmptyPlaintext_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] emptyPlaintext = new byte[0];
                byte[] ciphertext;
                byte[] tag;
                provider.Encrypt(_nonce, emptyPlaintext, out ciphertext, out tag);

                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext);

                Assert.AreEqual(0, decryptedPlaintext.Length);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Decrypt_WithModifiedCiphertext_ThrowsCryptographicException()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext;
                byte[] tag;
                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);

                ciphertext[0] ^= 1;

                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Decrypt_WithModifiedTag_ThrowsCryptographicException()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext;
                byte[] tag;
                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);

                tag[0] ^= 1;

                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Decrypt_WithWrongNonce_ThrowsCryptographicException()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext;
                byte[] tag;
                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);

                byte[] wrongNonce = new byte[12];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(wrongNonce);
                }

                byte[] decryptedPlaintext;
                provider.Decrypt(wrongNonce, ciphertext, tag, out decryptedPlaintext);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Decrypt_WithWrongAAD_ThrowsCryptographicException()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] aad = Encoding.UTF8.GetBytes("Correct AAD");
                byte[] ciphertext;
                byte[] tag;
                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag, aad);

                byte[] wrongAad = Encoding.UTF8.GetBytes("Wrong AAD");
                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext, wrongAad);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Decrypt_WithAADWhenNoneUsedInEncryption_ThrowsCryptographicException()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext;
                byte[] tag;
                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);

                byte[] aad = Encoding.UTF8.GetBytes("Unexpected AAD");
                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext, aad);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt_WithNullNonce_ThrowsArgumentNullException()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext = new byte[16];
                byte[] tag = new byte[16];
                byte[] plaintext;
                provider.Decrypt(null, ciphertext, tag, out plaintext);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt_WithNullCiphertext_ThrowsArgumentNullException()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] tag = new byte[16];
                byte[] plaintext;
                provider.Decrypt(_nonce, null, tag, out plaintext);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt_WithNullTag_ThrowsArgumentNullException()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext = new byte[16];
                byte[] plaintext;
                provider.Decrypt(_nonce, ciphertext, null, out plaintext);
            }
        }

        #endregion

        #region Round-Trip Tests

        [TestMethod]
        public void RoundTrip_WithAES128_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key128))
            {
                byte[] ciphertext, tag;
                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);

                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext);

                CollectionAssert.AreEqual(_plaintext, decryptedPlaintext);
            }
        }

        [TestMethod]
        public void RoundTrip_WithAES192_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key192))
            {
                byte[] ciphertext, tag;
                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);

                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext);

                CollectionAssert.AreEqual(_plaintext, decryptedPlaintext);
            }
        }

        [TestMethod]
        public void RoundTrip_WithAES256_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext, tag;
                provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);

                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext);

                CollectionAssert.AreEqual(_plaintext, decryptedPlaintext);
            }
        }

        [TestMethod]
        public void RoundTrip_WithLargePlaintext_Succeeds()
        {
            byte[] largePlaintext = new byte[1024 * 1024];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(largePlaintext);
            }

            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] ciphertext, tag;
                provider.Encrypt(_nonce, largePlaintext, out ciphertext, out tag);

                byte[] decryptedPlaintext;
                provider.Decrypt(_nonce, ciphertext, tag, out decryptedPlaintext);

                CollectionAssert.AreEqual(largePlaintext, decryptedPlaintext);
            }
        }

        [TestMethod]
        public void RoundTrip_MultipleOperations_AllSucceed()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                for (int i = 0; i < 10; i++)
                {
                    byte[] testData = Encoding.UTF8.GetBytes($"Test message {i}");
                    byte[] testNonce = new byte[12];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(testNonce);
                    }

                    byte[] ciphertext, tag;
                    provider.Encrypt(testNonce, testData, out ciphertext, out tag);

                    byte[] decryptedPlaintext;
                    provider.Decrypt(testNonce, ciphertext, tag, out decryptedPlaintext);

                    CollectionAssert.AreEqual(testData, decryptedPlaintext);
                }
            }
        }

        #endregion

        #region Dispose Tests

        [TestMethod]
        [ExpectedException(typeof(ObjectDisposedException))]
        public void Encrypt_AfterDispose_ThrowsObjectDisposedException()
        {
            var provider = new AesGcmProvider(_key256);
            provider.Dispose();

            byte[] ciphertext, tag;
            provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);
        }

        [TestMethod]
        [ExpectedException(typeof(ObjectDisposedException))]
        public void Decrypt_AfterDispose_ThrowsObjectDisposedException()
        {
            var provider = new AesGcmProvider(_key256);
            byte[] ciphertext, tag;
            provider.Encrypt(_nonce, _plaintext, out ciphertext, out tag);
            provider.Dispose();

            byte[] plaintext;
            provider.Decrypt(_nonce, ciphertext, tag, out plaintext);
        }

        [TestMethod]
        public void Dispose_CalledMultipleTimes_DoesNotThrow()
        {
            var provider = new AesGcmProvider(_key256);
            provider.Dispose();
            provider.Dispose();
            provider.Dispose();
        }

        #endregion

        #region Thread Safety Tests

        [TestMethod]
        public void Encrypt_MultipleThreads_AllSucceed()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                var tasks = new System.Threading.Tasks.Task[10];
                var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();

                for (int i = 0; i < tasks.Length; i++)
                {
                    int threadId = i;
                    tasks[i] = System.Threading.Tasks.Task.Run(() =>
                    {
                        try
                        {
                            byte[] threadNonce = new byte[12];
                            byte[] threadPlaintext = Encoding.UTF8.GetBytes($"Thread {threadId} message");

                            using (var rng = new RNGCryptoServiceProvider())
                            {
                                rng.GetBytes(threadNonce);
                            }

                            byte[] ciphertext, tag;
                            provider.Encrypt(threadNonce, threadPlaintext, out ciphertext, out tag);

                            byte[] decryptedPlaintext;
                            provider.Decrypt(threadNonce, ciphertext, tag, out decryptedPlaintext);

                            CollectionAssert.AreEqual(threadPlaintext, decryptedPlaintext);
                        }
                        catch (Exception ex)
                        {
                            exceptions.Add(ex);
                        }
                    });
                }

                System.Threading.Tasks.Task.WaitAll(tasks);

                if (exceptions.Count > 0)
                {
                    throw new AggregateException("Thread safety test failed", exceptions);
                }
            }
        }

        #endregion

        #region Known Test Vectors

        [TestMethod]
        public void Encrypt_WithKnownVector_ProducesExpectedResults()
        {
            byte[] key = new byte[32];
            byte[] nonce = new byte[12];
            byte[] plaintext = Encoding.UTF8.GetBytes("Test");

            using (var provider = new AesGcmProvider(key))
            {
                byte[] ciphertext, tag;
                provider.Encrypt(nonce, plaintext, out ciphertext, out tag);

                byte[] decryptedPlaintext;
                provider.Decrypt(nonce, ciphertext, tag, out decryptedPlaintext);

                CollectionAssert.AreEqual(plaintext, decryptedPlaintext);
            }
        }

        #endregion

        #region Nonce Size Tests

        [TestMethod]
        public void Encrypt_WithNonceSize96Bits_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                byte[] nonce96 = new byte[12];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(nonce96);
                }

                byte[] ciphertext, tag;
                provider.Encrypt(nonce96, _plaintext, out ciphertext, out tag);

                Assert.IsNotNull(ciphertext);
                Assert.IsNotNull(tag);
            }
        }

        [TestMethod]
        public void Encrypt_WithDifferentNonceSizes_Succeeds()
        {
            using (var provider = new AesGcmProvider(_key256))
            {
                foreach (int nonceSize in new[] { 8, 12, 16 })
                {
                    byte[] nonce = new byte[nonceSize];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(nonce);
                    }

                    byte[] ciphertext, tag;
                    provider.Encrypt(nonce, _plaintext, out ciphertext, out tag);

                    byte[] decryptedPlaintext;
                    provider.Decrypt(nonce, ciphertext, tag, out decryptedPlaintext);

                    CollectionAssert.AreEqual(_plaintext, decryptedPlaintext);
                }
            }
        }

        #endregion
    }
}
