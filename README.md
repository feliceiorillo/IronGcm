# IronGcm

A high-performance, thread-safe AES-GCM encryption library for .NET Framework 4.6.2+ using Windows CNG (Cryptography Next Generation) API via P/Invoke.

## Overview

IronGcm provides AES-GCM (Galois/Counter Mode) authenticated encryption without requiring external dependencies like BouncyCastle. It directly leverages the native Windows BCrypt API for optimal performance and security.

## Features

- ? **Native Windows CNG Integration** - Uses BCrypt API for hardware-accelerated encryption
- ? **No External Dependencies** - Pure .NET Framework 4.6.2 compatible implementation
- ? **Thread-Safe** - Safe for concurrent operations across multiple threads
- ? **Multiple Key Sizes** - Supports AES-128, AES-192, and AES-256
- ? **Authenticated Encryption** - Provides both confidentiality and authenticity
- ? **Additional Authenticated Data (AAD)** - Support for authenticated but unencrypted data
- ? **Proper Resource Management** - Implements IDisposable with SafeHandles

## Requirements

- .NET Framework 4.6.2 or higher
- Windows operating system (uses bcrypt.dll)

## Installation

Simply add the `AesGcmProvider.cs` file to your project, or reference the compiled IronGcm.dll assembly.

## Quick Start

### Basic Encryption/Decryption

```csharp
using System;
using System.Security.Cryptography;
using System.Text;
using IronGcm;

// Generate a random 256-bit key
byte[] key = new byte[32];
using (var rng = new RNGCryptoServiceProvider())
{
    rng.GetBytes(key);
}

// Create the provider (dispose when done)
using (var provider = new AesGcmProvider(key))
{
    // Generate a random 12-byte nonce (recommended for GCM)
    byte[] nonce = new byte[12];
    using (var rng = new RNGCryptoServiceProvider())
    {
        rng.GetBytes(nonce);
    }

    // Your plaintext data
    byte[] plaintext = Encoding.UTF8.GetBytes("Secret message");

    // Encrypt
    byte[] ciphertext;
    byte[] tag;
    provider.Encrypt(nonce, plaintext, out ciphertext, out tag);

    // Decrypt
    byte[] decrypted;
    provider.Decrypt(nonce, ciphertext, tag, out decrypted);

    // Verify
    string message = Encoding.UTF8.GetString(decrypted);
    Console.WriteLine(message); // Output: "Secret message"
}
```

### Encryption with Additional Authenticated Data (AAD)

```csharp
using (var provider = new AesGcmProvider(key))
{
    byte[] nonce = new byte[12];
    byte[] plaintext = Encoding.UTF8.GetBytes("Secret data");
    
    // AAD is authenticated but NOT encrypted
    byte[] aad = Encoding.UTF8.GetBytes("Public metadata");

    // Encrypt with AAD
    byte[] ciphertext;
    byte[] tag;
    provider.Encrypt(nonce, plaintext, out ciphertext, out tag, aad);

    // Decrypt (must use same AAD)
    byte[] decrypted;
    provider.Decrypt(nonce, ciphertext, tag, out decrypted, aad);
}
```

## API Reference

### Constructor

```csharp
public AesGcmProvider(byte[] key)
```

**Parameters:**
- `key`: The AES key. Must be 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256).

**Throws:**
- `ArgumentNullException`: If key is null
- `ArgumentException`: If key length is invalid
- `CryptographicException`: If initialization fails

### Encrypt Method

```csharp
public void Encrypt(
    byte[] nonce, 
    byte[] plaintext, 
    out byte[] ciphertext, 
    out byte[] tag, 
    byte[] associatedData = null)
```

**Parameters:**
- `nonce`: The nonce/IV. Recommended size is 12 bytes for optimal GCM performance.
- `plaintext`: The data to encrypt.
- `ciphertext`: [out] The encrypted data (same length as plaintext).
- `tag`: [out] The authentication tag (16 bytes).
- `associatedData`: Optional additional authenticated data (AAD) that is authenticated but not encrypted.

**Throws:**
- `ArgumentNullException`: If nonce or plaintext is null
- `ObjectDisposedException`: If provider has been disposed
- `CryptographicException`: If encryption fails

**Important Notes:**
- Never reuse the same nonce with the same key
- Store the nonce, ciphertext, and tag together for decryption
- The AAD (if used) must be available during decryption

### Decrypt Method

```csharp
public void Decrypt(
    byte[] nonce, 
    byte[] ciphertext, 
    byte[] tag, 
    out byte[] plaintext, 
    byte[] associatedData = null)
```

**Parameters:**
- `nonce`: The nonce/IV used during encryption.
- `ciphertext`: The encrypted data.
- `tag`: The authentication tag from encryption.
- `plaintext`: [out] The decrypted data.
- `associatedData`: Optional AAD used during encryption (must match exactly).

**Throws:**
- `ArgumentNullException`: If nonce, ciphertext, or tag is null
- `ObjectDisposedException`: If provider has been disposed
- `CryptographicException`: If authentication fails or decryption fails

**Important Notes:**
- If the tag verification fails, a `CryptographicException` is thrown
- This indicates the data has been tampered with or corrupted
- Never use decrypted data if verification fails

## Security Considerations

### Nonce Management

?? **CRITICAL**: Never reuse a nonce with the same key. Each encryption operation must use a unique nonce.

```csharp
// GOOD: Generate a new random nonce for each encryption
byte[] nonce = new byte[12];
using (var rng = new RNGCryptoServiceProvider())
{
    rng.GetBytes(nonce);
}

// BAD: Reusing the same nonce
byte[] nonce = new byte[12]; // All zeros - DO NOT USE THIS WAY
```

### Key Management

- Generate keys using a cryptographically secure random number generator
- Store keys securely (e.g., using Windows DPAPI, Azure Key Vault, or HSM)
- Never hardcode keys in source code
- Rotate keys periodically

```csharp
// Generate a secure random key
byte[] key = new byte[32]; // AES-256
using (var rng = new RNGCryptoServiceProvider())
{
    rng.GetBytes(key);
}

// Store securely (example using DPAPI)
byte[] protectedKey = ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
```

### Tag Size

The library uses a 128-bit (16-byte) authentication tag, which provides strong security guarantees. This is the recommended size for GCM mode.

### Nonce Size

While GCM supports various nonce sizes, **12 bytes (96 bits)** is recommended for optimal performance and security:
- Nonces of other sizes require additional processing
- 12-byte nonces allow for billions of encryptions with the same key (if using random nonces)

## Thread Safety

The `AesGcmProvider` class is thread-safe. Multiple threads can safely call `Encrypt` and `Decrypt` methods on the same instance simultaneously.

```csharp
using (var provider = new AesGcmProvider(key))
{
    // Safe to use from multiple threads
    Parallel.For(0, 100, i =>
    {
        byte[] nonce = new byte[12];
        byte[] plaintext = Encoding.UTF8.GetBytes($"Message {i}");
        
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(nonce);
        }

        byte[] ciphertext, tag;
        provider.Encrypt(nonce, plaintext, out ciphertext, out tag);
    });
}
```

## Performance Considerations

- **Reuse Provider Instances**: Create one `AesGcmProvider` instance and reuse it for multiple operations instead of creating a new instance for each encryption/decryption.
- **Hardware Acceleration**: The native BCrypt API automatically uses hardware-accelerated AES-NI instructions when available.
- **Memory Allocation**: The library allocates new byte arrays for output. Consider pooling arrays for high-throughput scenarios.

## Common Patterns

### Storing Encrypted Data

```csharp
// Combine nonce + ciphertext + tag for storage
byte[] combined = new byte[nonce.Length + ciphertext.Length + tag.Length];
Buffer.BlockCopy(nonce, 0, combined, 0, nonce.Length);
Buffer.BlockCopy(ciphertext, 0, combined, nonce.Length, ciphertext.Length);
Buffer.BlockCopy(tag, 0, combined, nonce.Length + ciphertext.Length, tag.Length);

// Save to file, database, etc.
File.WriteAllBytes("encrypted.bin", combined);
```

### Retrieving Encrypted Data

```csharp
// Read combined data
byte[] combined = File.ReadAllBytes("encrypted.bin");

// Extract components
byte[] nonce = new byte[12];
byte[] tag = new byte[16];
byte[] ciphertext = new byte[combined.Length - 12 - 16];

Buffer.BlockCopy(combined, 0, nonce, 0, 12);
Buffer.BlockCopy(combined, 12, ciphertext, 0, ciphertext.Length);
Buffer.BlockCopy(combined, 12 + ciphertext.Length, tag, 0, 16);

// Decrypt
using (var provider = new AesGcmProvider(key))
{
    byte[] plaintext;
    provider.Decrypt(nonce, ciphertext, tag, out plaintext);
}
```

### Encrypting Strings

```csharp
public static class StringEncryption
{
    public static byte[] EncryptString(AesGcmProvider provider, string plaintext)
    {
        byte[] nonce = new byte[12];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(nonce);
        }

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] ciphertext, tag;
        provider.Encrypt(nonce, plaintextBytes, out ciphertext, out tag);

        // Combine for storage
        byte[] result = new byte[nonce.Length + ciphertext.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + ciphertext.Length, tag.Length);

        return result;
    }

    public static string DecryptString(AesGcmProvider provider, byte[] encrypted)
    {
        byte[] nonce = new byte[12];
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[encrypted.Length - 12 - 16];

        Buffer.BlockCopy(encrypted, 0, nonce, 0, 12);
        Buffer.BlockCopy(encrypted, 12, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(encrypted, 12 + ciphertext.Length, tag, 0, 16);

        byte[] plaintext;
        provider.Decrypt(nonce, ciphertext, tag, out plaintext);

        return Encoding.UTF8.GetString(plaintext);
    }
}
```

## Error Handling

```csharp
try
{
    using (var provider = new AesGcmProvider(key))
    {
        byte[] plaintext;
        provider.Decrypt(nonce, ciphertext, tag, out plaintext);
        // Use plaintext...
    }
}
catch (CryptographicException ex)
{
    // Authentication failed - data has been tampered with or corrupted
    Console.WriteLine("Decryption failed: " + ex.Message);
    // DO NOT use any decrypted data
}
catch (ObjectDisposedException ex)
{
    // Provider was already disposed
    Console.WriteLine("Provider disposed: " + ex.Message);
}
```

## Limitations

- **Windows Only**: Requires Windows OS (uses bcrypt.dll)
- **.NET Framework**: Targets .NET Framework 4.6.2+ (not .NET Core/5+)
- **No Async**: Operations are synchronous only

## Testing

The library includes comprehensive unit tests covering:
- All key sizes (128, 192, 256-bit)
- Empty and large plaintexts
- AAD scenarios
- Authentication tag validation
- Thread safety
- Error conditions
- Round-trip encryption/decryption

Run tests using:
```
dotnet test
```
or via Visual Studio Test Explorer.

## License

[Specify your license here]

## Contributing

[Specify contribution guidelines here]

## Support

[Specify support channels here]

## See Also

- [NIST SP 800-38D - GCM Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Windows BCrypt API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/)
- [AES-GCM Security Considerations](https://crypto.stackexchange.com/questions/26790/how-bad-it-is-using-the-same-iv-twice-with-aes-gcm)
