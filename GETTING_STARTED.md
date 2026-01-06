# Getting Started with IronGcm

This guide will help you quickly get started with IronGcm for AES-GCM encryption in your .NET Framework 4.6.2+ application.

## Installation

### Option 1: Add Source File

1. Copy `AesGcmProvider.cs` to your project
2. Add a reference to `System.Security` (for cryptographic types)
3. Add a reference to `Microsoft.Win32` (for SafeHandles)

### Option 2: Reference DLL

1. Build the IronGcm project
2. Add a reference to `IronGcm.dll` in your project

## First Example: Encrypt and Decrypt a Message

```csharp
using System;
using System.Security.Cryptography;
using System.Text;
using IronGcm;

class Program
{
    static void Main()
    {
        // 1. Generate a secure random key (do this once, store securely)
        byte[] key = new byte[32]; // 32 bytes = AES-256
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(key);
        }

        // 2. Create the AES-GCM provider
        using (var gcm = new AesGcmProvider(key))
        {
            // 3. Prepare your message
            string secretMessage = "Hello, this is a secret message!";
            byte[] plaintext = Encoding.UTF8.GetBytes(secretMessage);

            // 4. Generate a unique nonce for this encryption
            byte[] nonce = new byte[12]; // 12 bytes recommended for GCM
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(nonce);
            }

            // 5. Encrypt
            byte[] ciphertext;
            byte[] tag;
            gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);

            Console.WriteLine("Encryption successful!");
            Console.WriteLine($"Ciphertext: {BitConverter.ToString(ciphertext)}");
            Console.WriteLine($"Tag: {BitConverter.ToString(tag)}");

            // 6. Decrypt
            byte[] decryptedBytes;
            gcm.Decrypt(nonce, ciphertext, tag, out decryptedBytes);

            string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine($"Decrypted: {decryptedMessage}");
        }
    }
}
```

## Step-by-Step Explanation

### Step 1: Generate a Key

```csharp
byte[] key = new byte[32]; // Choose 16, 24, or 32 for AES-128/192/256
using (var rng = new RNGCryptoServiceProvider())
{
    rng.GetBytes(key);
}
```

**Important:**
- Generate the key once and store it securely
- Use 32 bytes (256 bits) for maximum security
- Never hardcode keys in your source code

### Step 2: Create Provider

```csharp
using (var gcm = new AesGcmProvider(key))
{
    // Use gcm for multiple encrypt/decrypt operations
}
```

**Important:**
- Always use `using` statement for proper resource cleanup
- Reuse the same provider for multiple operations
- The provider is thread-safe

### Step 3: Generate Nonce

```csharp
byte[] nonce = new byte[12];
using (var rng = new RNGCryptoServiceProvider())
{
    rng.GetBytes(nonce);
}
```

**Important:**
- Generate a NEW nonce for EVERY encryption
- Never reuse a nonce with the same key
- Use 12 bytes for optimal performance

### Step 4: Encrypt

```csharp
byte[] ciphertext;
byte[] tag;
gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);
```

**What you get:**
- `ciphertext`: The encrypted data (same size as plaintext)
- `tag`: The authentication tag (16 bytes)

### Step 5: Store or Transmit

You need to save/send three things:
- The nonce (12 bytes)
- The ciphertext (variable length)
- The tag (16 bytes)

The key should NEVER be stored with the encrypted data.

### Step 6: Decrypt

```csharp
byte[] decryptedBytes;
gcm.Decrypt(nonce, ciphertext, tag, out decryptedBytes);
```

**Important:**
- Use the SAME nonce used for encryption
- If the tag doesn't match, an exception is thrown
- This means the data was tampered with - do NOT use it

## Common Use Cases

### Use Case 1: Encrypting a File

```csharp
using System.IO;
using IronGcm;

public void EncryptFile(string inputPath, string outputPath, byte[] key)
{
    // Read the file
    byte[] plaintext = File.ReadAllBytes(inputPath);

    using (var gcm = new AesGcmProvider(key))
    {
        // Generate nonce
        byte[] nonce = new byte[12];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(nonce);
        }

        // Encrypt
        byte[] ciphertext;
        byte[] tag;
        gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);

        // Combine nonce + ciphertext + tag
        using (var fs = new FileStream(outputPath, FileMode.Create))
        {
            fs.Write(nonce, 0, nonce.Length);
            fs.Write(ciphertext, 0, ciphertext.Length);
            fs.Write(tag, 0, tag.Length);
        }
    }
}

public void DecryptFile(string inputPath, string outputPath, byte[] key)
{
    byte[] encrypted = File.ReadAllBytes(inputPath);

    // Extract components
    byte[] nonce = new byte[12];
    byte[] tag = new byte[16];
    byte[] ciphertext = new byte[encrypted.Length - 28];

    Buffer.BlockCopy(encrypted, 0, nonce, 0, 12);
    Buffer.BlockCopy(encrypted, 12, ciphertext, 0, ciphertext.Length);
    Buffer.BlockCopy(encrypted, 12 + ciphertext.Length, tag, 0, 16);

    using (var gcm = new AesGcmProvider(key))
    {
        byte[] plaintext;
        gcm.Decrypt(nonce, ciphertext, tag, out plaintext);
        File.WriteAllBytes(outputPath, plaintext);
    }
}
```

### Use Case 2: Encrypting Database Fields

```csharp
public class SecureUserRepository
{
    private readonly byte[] _encryptionKey;
    private readonly AesGcmProvider _gcm;

    public SecureUserRepository(byte[] encryptionKey)
    {
        _encryptionKey = encryptionKey;
        _gcm = new AesGcmProvider(encryptionKey);
    }

    public byte[] EncryptSensitiveData(string data)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(data);
        byte[] nonce = new byte[12];
        
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(nonce);
        }

        byte[] ciphertext, tag;
        _gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);

        // Combine for storage
        byte[] result = new byte[nonce.Length + ciphertext.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + ciphertext.Length, tag.Length);

        return result;
    }

    public string DecryptSensitiveData(byte[] encrypted)
    {
        byte[] nonce = new byte[12];
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[encrypted.Length - 28];

        Buffer.BlockCopy(encrypted, 0, nonce, 0, 12);
        Buffer.BlockCopy(encrypted, 12, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(encrypted, 12 + ciphertext.Length, tag, 0, 16);

        byte[] plaintext;
        _gcm.Decrypt(nonce, ciphertext, tag, out plaintext);

        return Encoding.UTF8.GetString(plaintext);
    }

    public void Dispose()
    {
        _gcm?.Dispose();
    }
}
```

### Use Case 3: Encrypting with Additional Authenticated Data (AAD)

AAD is data that needs to be authenticated but NOT encrypted (like metadata).

```csharp
public byte[] EncryptWithMetadata(string message, string userId)
{
    using (var gcm = new AesGcmProvider(key))
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(message);
        byte[] nonce = new byte[12];
        byte[] aad = Encoding.UTF8.GetBytes(userId); // Authenticated, not encrypted
        
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(nonce);
        }

        byte[] ciphertext, tag;
        gcm.Encrypt(nonce, plaintext, out ciphertext, out tag, aad);

        // Store: nonce + userId.Length + userId + ciphertext + tag
        using (var ms = new MemoryStream())
        using (var writer = new BinaryWriter(ms))
        {
            writer.Write(nonce);
            writer.Write(aad.Length);
            writer.Write(aad);
            writer.Write(ciphertext);
            writer.Write(tag);
            return ms.ToArray();
        }
    }
}

public string DecryptWithMetadata(byte[] encrypted, out string userId)
{
    using (var ms = new MemoryStream(encrypted))
    using (var reader = new BinaryReader(ms))
    {
        byte[] nonce = reader.ReadBytes(12);
        int aadLength = reader.ReadInt32();
        byte[] aad = reader.ReadBytes(aadLength);
        byte[] ciphertext = reader.ReadBytes((int)(ms.Length - ms.Position - 16));
        byte[] tag = reader.ReadBytes(16);

        userId = Encoding.UTF8.GetString(aad);

        using (var gcm = new AesGcmProvider(key))
        {
            byte[] plaintext;
            gcm.Decrypt(nonce, ciphertext, tag, out plaintext, aad);
            return Encoding.UTF8.GetString(plaintext);
        }
    }
}
```

## Best Practices Checklist

? **DO:**
- Generate a new random nonce for every encryption operation
- Use a cryptographically secure random number generator (RNGCryptoServiceProvider)
- Use 32-byte keys (AES-256) for maximum security
- Store keys securely (DPAPI, Key Vault, HSM)
- Use `using` statements to ensure proper disposal
- Handle CryptographicException during decryption (indicates tampering)
- Keep nonce, ciphertext, and tag together for storage/transmission

? **DON'T:**
- Reuse nonces with the same key
- Hardcode keys in source code
- Store keys with encrypted data
- Ignore authentication failures
- Use predictable or sequential nonces
- Use keys shorter than 32 bytes for new applications

## Troubleshooting

### "Authentication tag mismatch" Exception

**Cause:** The data has been modified, corrupted, or you're using wrong parameters.

**Check:**
- Are you using the correct key?
- Is the nonce the same one used during encryption?
- Is the AAD (if used) exactly the same?
- Has the ciphertext or tag been modified?

### "BCryptOpenAlgorithmProvider failed" Exception

**Cause:** System cannot initialize the BCrypt provider.

**Solutions:**
- Ensure you're running on Windows
- Check that bcrypt.dll is available (should be on all modern Windows)
- Run as administrator if there are permission issues

### Out of Memory with Large Files

**Solution:** For very large files, consider encrypting in chunks or using streaming approaches.

## Next Steps

- Read the [README.md](README.md) for full API documentation
- Review security considerations
- Check out the test project for more examples
- Implement proper key management for your application

## Support

For issues, questions, or contributions, please [specify your support channel].
