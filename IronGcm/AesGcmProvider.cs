using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace IronGcm
{
    /// <summary>
    /// Provides AES-GCM encryption and decryption using Windows CNG (BCrypt) API.
    /// Thread-safe implementation compatible with .NET Framework 4.6.2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class provides authenticated encryption with associated data (AEAD) using the AES-GMC algorithm.
    /// It leverages the native Windows Cryptography Next Generation (CNG) API for optimal performance and security.
    /// </para>
    /// <para>
    /// <strong>Important Security Notes:</strong>
    /// <list type="bullet">
    /// <item><description>Never reuse a nonce with the same key. Each encryption operation must use a unique nonce.</description></item>
    /// <item><description>Use a cryptographically secure random number generator (e.g., RNGCryptoServiceProvider) for keys and nonces.</description></item>
    /// <item><description>The recommended nonce size is 12 bytes (96 bits) for optimal GCM performance.</description></item>
    /// <item><description>Store keys securely using Windows DPAPI, Azure Key Vault, or a Hardware Security Module.</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// This class is thread-safe and can be used concurrently from multiple threads.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Generate a secure random key
    /// byte[] key = new byte[32]; // AES-256
    /// using (var rng = new RNGCryptoServiceProvider())
    /// {
    ///     rng.GetBytes(key);
    /// }
    /// 
    /// using (var provider = new AesGcmProvider(key))
    /// {
    ///     // Generate a unique nonce
    ///     byte[] nonce = new byte[12];
    ///     using (var rng = new RNGCryptoServiceProvider())
    ///     {
    ///         rng.GetBytes(nonce);
    ///     }
    ///     
    ///     byte[] plaintext = Encoding.UTF8.GetBytes("Secret message");
    ///     byte[] ciphertext, tag;
    ///     
    ///     // Encrypt
    ///     provider.Encrypt(nonce, plaintext, out ciphertext, out tag);
    ///     
    ///     // Decrypt
    ///     byte[] decrypted;
    ///     provider.Decrypt(nonce, ciphertext, tag, out decrypted);
    /// }
    /// </code>
    /// </example>
    public sealed class AesGcmProvider : IDisposable
    {
        private const string BCRYPT_AES_ALGORITHM = "AES";
        private const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
        
        private readonly BCryptAlgorithmHandle _algorithmHandle;
        private readonly byte[] _keyData;
        private readonly object _lock = new object();
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of AesGcmProvider with the specified key.
        /// </summary>
        /// <param name="key">The AES key (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256).</param>
        /// <exception cref="ArgumentNullException">Thrown when key is null.</exception>
        /// <exception cref="ArgumentException">Thrown when key length is not 16, 24, or 32 bytes.</exception>
        /// <exception cref="CryptographicException">Thrown when algorithm provider or key generation fails.</exception>
        public AesGcmProvider(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("Key must be 16, 24, or 32 bytes.", nameof(key));

            _keyData = new byte[key.Length];
            Array.Copy(key, _keyData, key.Length);

            try
            {
                // Open algorithm provider
                uint status = BCryptOpenAlgorithmProvider(
                    out _algorithmHandle,
                    BCRYPT_AES_ALGORITHM,
                    null,
                    0);
                
                if (status != STATUS_SUCCESS)
                    throw new CryptographicException($"BCryptOpenAlgorithmProvider failed with NTSTATUS: 0x{status:X8}");

                // Set chaining mode to GCM
                byte[] gcmMode = System.Text.Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_GCM);
                status = BCryptSetProperty(
                    _algorithmHandle,
                    "ChainingMode",
                    gcmMode,
                    gcmMode.Length,
                    0);

                if (status != STATUS_SUCCESS)
                    throw new CryptographicException($"BCryptSetProperty failed with NTSTATUS: 0x{status:X8}");
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        /// <summary>
        /// Encrypts plaintext using AES-GCM.
        /// </summary>
        /// <param name="nonce">The nonce/IV (typically 12 bytes for GCM).</param>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="ciphertext">The encrypted data (same length as plaintext).</param>
        /// <param name="tag">The authentication tag (typically 16 bytes).</param>
        /// <param name="associatedData">Optional additional authenticated data (AAD).</param>
        /// <remarks>
        /// <para>
        /// The nonce must be unique for each encryption operation with the same key. Never reuse nonces.
        /// A recommended approach is to generate a random 12-byte nonce using RNGCryptoServiceProvider.
        /// </para>
        /// <para>
        /// The Additional Authenticated Data (AAD) is authenticated but not encrypted. It can be used
        /// to bind metadata to the encrypted message without encrypting the metadata itself.
        /// </para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">Thrown when nonce or plaintext is null.</exception>
        /// <exception cref="ObjectDisposedException">Thrown when the provider has been disposed.</exception>
        /// <exception cref="CryptographicException">Thrown when encryption fails.</exception>
        public void Encrypt(byte[] nonce, byte[] plaintext, out byte[] ciphertext, out byte[] tag, byte[] associatedData = null)
        {
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            lock (_lock)
            {
                ThrowIfDisposed();

                const int tagSize = 16;
                ciphertext = new byte[plaintext.Length];
                tag = new byte[tagSize];

                // Create a new key handle for this operation
                BCryptKeyHandle keyHandle;
                uint status = BCryptGenerateSymmetricKey(
                    _algorithmHandle,
                    out keyHandle,
                    IntPtr.Zero,
                    0,
                    _keyData,
                    _keyData.Length,
                    0);

                if (status != STATUS_SUCCESS)
                    throw new CryptographicException($"BCryptGenerateSymmetricKey failed with NTSTATUS: 0x{status:X8}");

                try
                {
                    GCHandle nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                    GCHandle aadHandle = (associatedData != null && associatedData.Length > 0) ? GCHandle.Alloc(associatedData, GCHandleType.Pinned) : default(GCHandle);
                    GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
                    GCHandle plaintextHandle = plaintext.Length > 0 ? GCHandle.Alloc(plaintext, GCHandleType.Pinned) : default(GCHandle);
                    GCHandle ciphertextHandle = ciphertext.Length > 0 ? GCHandle.Alloc(ciphertext, GCHandleType.Pinned) : default(GCHandle);

                    try
                    {
                        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                        authInfo.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                        authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
                        authInfo.pbNonce = nonceHandle.AddrOfPinnedObject();
                        authInfo.cbNonce = nonce.Length;
                        authInfo.pbTag = tagHandle.AddrOfPinnedObject();
                        authInfo.cbTag = tag.Length;
                        
                        if (associatedData != null && associatedData.Length > 0)
                        {
                            authInfo.pbAuthData = aadHandle.AddrOfPinnedObject();
                            authInfo.cbAuthData = associatedData.Length;
                        }
                        else
                        {
                            authInfo.pbAuthData = IntPtr.Zero;
                            authInfo.cbAuthData = 0;
                        }
                        
                        authInfo.pbMacContext = IntPtr.Zero;
                        authInfo.cbMacContext = 0;
                        authInfo.cbAAD = 0;
                        authInfo.cbData = 0;
                        authInfo.dwFlags = 0;

                        int bytesWritten;
                        status = BCryptEncrypt(
                            keyHandle,
                            plaintext.Length > 0 ? plaintext : null,
                            plaintext.Length,
                            ref authInfo,
                            IntPtr.Zero,
                            0,
                            ciphertext.Length > 0 ? ciphertext : null,
                            ciphertext.Length,
                            out bytesWritten,
                            0);

                        if (status != STATUS_SUCCESS)
                            throw new CryptographicException($"BCryptEncrypt failed with NTSTATUS: 0x{status:X8}");

                        if (bytesWritten != plaintext.Length)
                            throw new CryptographicException($"Unexpected ciphertext length: {bytesWritten} (expected {plaintext.Length})");
                    }
                    finally
                    {
                        if (nonceHandle.IsAllocated) nonceHandle.Free();
                        if (aadHandle.IsAllocated) aadHandle.Free();
                        if (tagHandle.IsAllocated) tagHandle.Free();
                        if (plaintextHandle.IsAllocated) plaintextHandle.Free();
                        if (ciphertextHandle.IsAllocated) ciphertextHandle.Free();
                    }
                }
                finally
                {
                    keyHandle?.Dispose();
                }
            }
        }

        /// <summary>
        /// Decrypts ciphertext using AES-GCM and validates the authentication tag.
        /// </summary>
        /// <param name="nonce">The nonce/IV used during encryption.</param>
        /// <param name="ciphertext">The encrypted data.</param>
        /// <param name="tag">The authentication tag to validate.</param>
        /// <param name="plaintext">The decrypted data.</param>
        /// <param name="associatedData">Optional additional authenticated data (AAD) used during encryption.</param>
        /// <remarks>
        /// <para>
        /// This method verifies the authentication tag before returning the decrypted data. If the tag
        /// verification fails, a CryptographicException is thrown, indicating that the data has been
        /// tampered with or corrupted. In this case, the decrypted data should NOT be used.
        /// </para>
        /// <para>
        /// The nonce and AAD must exactly match the values used during encryption.
        /// </para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">Thrown when nonce, ciphertext, or tag is null.</exception>
        /// <exception cref="ObjectDisposedException">Thrown when the provider has been disposed.</exception>
        /// <exception cref="CryptographicException">
        /// Thrown when authentication fails (tag mismatch) or decryption fails.
        /// A tag mismatch indicates the data has been tampered with.
        /// </exception>
        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, out byte[] plaintext, byte[] associatedData = null)
        {
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));
            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));
            if (tag == null)
                throw new ArgumentNullException(nameof(tag));

            lock (_lock)
            {
                ThrowIfDisposed();

                plaintext = new byte[ciphertext.Length];

                // Create a new key handle for this operation
                BCryptKeyHandle keyHandle;
                uint status = BCryptGenerateSymmetricKey(
                    _algorithmHandle,
                    out keyHandle,
                    IntPtr.Zero,
                    0,
                    _keyData,
                    _keyData.Length,
                    0);

                if (status != STATUS_SUCCESS)
                    throw new CryptographicException($"BCryptGenerateSymmetricKey failed with NTSTATUS: 0x{status:X8}");

                try
                {
                    GCHandle nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                    GCHandle aadHandle = (associatedData != null && associatedData.Length > 0) ? GCHandle.Alloc(associatedData, GCHandleType.Pinned) : default(GCHandle);
                    GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
                    GCHandle ciphertextHandle = ciphertext.Length > 0 ? GCHandle.Alloc(ciphertext, GCHandleType.Pinned) : default(GCHandle);
                    GCHandle plaintextHandle = plaintext.Length > 0 ? GCHandle.Alloc(plaintext, GCHandleType.Pinned) : default(GCHandle);

                    try
                    {
                        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                        authInfo.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                        authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
                        authInfo.pbNonce = nonceHandle.AddrOfPinnedObject();
                        authInfo.cbNonce = nonce.Length;
                        authInfo.pbTag = tagHandle.AddrOfPinnedObject();
                        authInfo.cbTag = tag.Length;
                        
                        if (associatedData != null && associatedData.Length > 0)
                        {
                            authInfo.pbAuthData = aadHandle.AddrOfPinnedObject();
                            authInfo.cbAuthData = associatedData.Length;
                        }
                        else
                        {
                            authInfo.pbAuthData = IntPtr.Zero;
                            authInfo.cbAuthData = 0;
                        }
                        
                        authInfo.pbMacContext = IntPtr.Zero;
                        authInfo.cbMacContext = 0;
                        authInfo.cbAAD = 0;
                        authInfo.cbData = 0;
                        authInfo.dwFlags = 0;

                        int bytesWritten;
                        status = BCryptDecrypt(
                            keyHandle,
                            ciphertext.Length > 0 ? ciphertext : null,
                            ciphertext.Length,
                            ref authInfo,
                            IntPtr.Zero,
                            0,
                            plaintext.Length > 0 ? plaintext : null,
                            plaintext.Length,
                            out bytesWritten,
                            0);

                        if (status == STATUS_AUTH_TAG_MISMATCH)
                            throw new CryptographicException("Authentication tag mismatch. The ciphertext or tag has been tampered with.");

                        if (status != STATUS_SUCCESS)
                            throw new CryptographicException($"BCryptDecrypt failed with NTSTATUS: 0x{status:X8}");

                        if (bytesWritten != ciphertext.Length)
                            throw new CryptographicException($"Unexpected plaintext length: {bytesWritten} (expected {ciphertext.Length})");
                    }
                    finally
                    {
                        if (nonceHandle.IsAllocated) nonceHandle.Free();
                        if (aadHandle.IsAllocated) aadHandle.Free();
                        if (tagHandle.IsAllocated) tagHandle.Free();
                        if (ciphertextHandle.IsAllocated) ciphertextHandle.Free();
                        if (plaintextHandle.IsAllocated) plaintextHandle.Free();
                    }
                }
                finally
                {
                    keyHandle?.Dispose();
                }
            }
        }

        /// <summary>
        /// Throws an ObjectDisposedException if this instance has been disposed.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Thrown when the provider has been disposed.</exception>
        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(AesGcmProvider));
        }

        /// <summary>
        /// Releases all resources used by the AesGcmProvider.
        /// </summary>
        /// <remarks>
        /// This method can be called multiple times safely. After disposal, any attempt to use
        /// the Encrypt or Decrypt methods will throw an ObjectDisposedException.
        /// </remarks>
        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            if (_keyData != null)
                Array.Clear(_keyData, 0, _keyData.Length);

            _algorithmHandle?.Dispose();
        }

        #region Native Interop

        private const uint STATUS_SUCCESS = 0x00000000;
        private const uint STATUS_AUTH_TAG_MISMATCH = 0xC000A002;
        private const int BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1;

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public int dwFlags;
        }

        private sealed class BCryptAlgorithmHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private BCryptAlgorithmHandle() : base(true) { }

            protected override bool ReleaseHandle()
            {
                return BCryptCloseAlgorithmProvider(handle, 0) == STATUS_SUCCESS;
            }
        }

        private sealed class BCryptKeyHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private BCryptKeyHandle() : base(true) { }

            protected override bool ReleaseHandle()
            {
                return BCryptDestroyKey(handle) == STATUS_SUCCESS;
            }
        }

        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern uint BCryptOpenAlgorithmProvider(
            out BCryptAlgorithmHandle phAlgorithm,
            [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
            [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation,
            uint dwFlags);

        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern uint BCryptCloseAlgorithmProvider(
            IntPtr hAlgorithm,
            uint dwFlags);

        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        private static extern uint BCryptSetProperty(
            BCryptAlgorithmHandle hObject,
            string pszProperty,
            byte[] pbInput,
            int cbInput,
            uint dwFlags);

        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern uint BCryptGenerateSymmetricKey(
            BCryptAlgorithmHandle hAlgorithm,
            out BCryptKeyHandle phKey,
            IntPtr pbKeyObject,
            int cbKeyObject,
            [In] byte[] pbSecret,
            int cbSecret,
            uint dwFlags);

        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern uint BCryptEncrypt(
            BCryptKeyHandle hKey,
            [In] byte[] pbInput,
            int cbInput,
            ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
            IntPtr pbIV,
            int cbIV,
            [Out] byte[] pbOutput,
            int cbOutput,
            out int pcbResult,
            uint dwFlags);

        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern uint BCryptDecrypt(
            BCryptKeyHandle hKey,
            [In] byte[] pbInput,
            int cbInput,
            ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
            IntPtr pbIV,
            int cbIV,
            [Out] byte[] pbOutput,
            int cbOutput,
            out int pcbResult,
            uint dwFlags);

        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern uint BCryptDestroyKey(IntPtr hKey);

        #endregion
    }
}
