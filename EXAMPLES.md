# IronGcm Examples

This document contains practical examples of using IronGcm in various scenarios.

## Table of Contents

1. [Basic Encryption/Decryption](#basic-encryptiondecryption)
2. [Working with Strings](#working-with-strings)
3. [File Encryption](#file-encryption)
4. [Encrypting with Additional Authenticated Data](#encrypting-with-additional-authenticated-data)
5. [Key Management](#key-management)
6. [Database Integration](#database-integration)
7. [Bulk Operations](#bulk-operations)
8. [Error Handling](#error-handling)

---

## Basic Encryption/Decryption

### Simple Message Encryption

```csharp
using System;
using System.Security.Cryptography;
using System.Text;
using IronGcm;

public class BasicExample
{
    public static void Main()
    {
        // Generate a random 256-bit key
        byte[] key = new byte[32];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(key);
        }

        // Create provider instance
        using (var gcm = new AesGcmProvider(key))
        {
            // Your message
            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, World!");

            // Generate a unique nonce
            byte[] nonce = new byte[12];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(nonce);
            }

            // Encrypt
            byte[] ciphertext, tag;
            gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);

            Console.WriteLine($"Original: {Encoding.UTF8.GetString(plaintext)}");
            Console.WriteLine($"Encrypted: {Convert.ToBase64String(ciphertext)}");

            // Decrypt
            byte[] decrypted;
            gcm.Decrypt(nonce, ciphertext, tag, out decrypted);

            Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");
        }
    }
}
```

---

## Working with Strings

### String Encryption Helper Class

```csharp
using System;
using System.Security.Cryptography;
using System.Text;
using IronGcm;

public class StringEncryptionHelper : IDisposable
{
    private readonly AesGcmProvider _provider;

    public StringEncryptionHelper(byte[] key)
    {
        _provider = new AesGcmProvider(key);
    }

    /// <summary>
    /// Encrypts a string and returns the result as a Base64-encoded string containing nonce + ciphertext + tag.
    /// </summary>
    public string EncryptString(string plaintext)
    {
        if (string.IsNullOrEmpty(plaintext))
            return string.Empty;

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] nonce = new byte[12];

        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(nonce);
        }

        byte[] ciphertext, tag;
        _provider.Encrypt(nonce, plaintextBytes, out ciphertext, out tag);

        // Combine: nonce (12) + ciphertext (variable) + tag (16)
        byte[] combined = new byte[12 + ciphertext.Length + 16];
        Buffer.BlockCopy(nonce, 0, combined, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, combined, 12, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, combined, 12 + ciphertext.Length, 16);

        return Convert.ToBase64String(combined);
    }

    /// <summary>
    /// Decrypts a Base64-encoded string containing nonce + ciphertext + tag.
    /// </summary>
    public string DecryptString(string encryptedBase64)
    {
        if (string.IsNullOrEmpty(encryptedBase64))
            return string.Empty;

        byte[] combined = Convert.FromBase64String(encryptedBase64);

        if (combined.Length < 28) // Minimum: 12 (nonce) + 0 (ciphertext) + 16 (tag)
            throw new ArgumentException("Invalid encrypted data");

        byte[] nonce = new byte[12];
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[combined.Length - 28];

        Buffer.BlockCopy(combined, 0, nonce, 0, 12);
        Buffer.BlockCopy(combined, 12, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(combined, 12 + ciphertext.Length, tag, 0, 16);

        byte[] plaintext;
        _provider.Decrypt(nonce, ciphertext, tag, out plaintext);

        return Encoding.UTF8.GetString(plaintext);
    }

    public void Dispose()
    {
        _provider?.Dispose();
    }
}

// Usage
class Program
{
    static void Main()
    {
        byte[] key = new byte[32];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(key);
        }

        using (var helper = new StringEncryptionHelper(key))
        {
            string encrypted = helper.EncryptString("My secret data");
            Console.WriteLine($"Encrypted: {encrypted}");

            string decrypted = helper.DecryptString(encrypted);
            Console.WriteLine($"Decrypted: {decrypted}");
        }
    }
}
```

---

## File Encryption

### Encrypting and Decrypting Files

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using IronGcm;

public class FileEncryption
{
    /// <summary>
    /// Encrypts a file and saves it with .encrypted extension.
    /// Format: [12 bytes nonce][variable bytes ciphertext][16 bytes tag]
    /// </summary>
    public static void EncryptFile(string inputPath, byte[] key)
    {
        string outputPath = inputPath + ".encrypted";

        // Read the entire file
        byte[] plaintext = File.ReadAllBytes(inputPath);

        using (var gcm = new AesGcmProvider(key))
        {
            // Generate random nonce
            byte[] nonce = new byte[12];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(nonce);
            }

            // Encrypt
            byte[] ciphertext, tag;
            gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);

            // Write to file: nonce + ciphertext + tag
            using (var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                fs.Write(nonce, 0, 12);
                fs.Write(ciphertext, 0, ciphertext.Length);
                fs.Write(tag, 0, 16);
            }

            Console.WriteLine($"File encrypted: {outputPath}");
        }

        // Securely clear plaintext from memory
        Array.Clear(plaintext, 0, plaintext.Length);
    }

    /// <summary>
    /// Decrypts a file encrypted with EncryptFile.
    /// </summary>
    public static void DecryptFile(string encryptedPath, byte[] key)
    {
        string outputPath = encryptedPath.Replace(".encrypted", ".decrypted");

        // Read the encrypted file
        byte[] encrypted = File.ReadAllBytes(encryptedPath);

        if (encrypted.Length < 28)
            throw new InvalidDataException("File is too small to be valid encrypted data");

        // Extract components
        byte[] nonce = new byte[12];
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[encrypted.Length - 28];

        Buffer.BlockCopy(encrypted, 0, nonce, 0, 12);
        Buffer.BlockCopy(encrypted, 12, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(encrypted, encrypted.Length - 16, tag, 0, 16);

        using (var gcm = new AesGcmProvider(key))
        {
            byte[] plaintext;
            gcm.Decrypt(nonce, ciphertext, tag, out plaintext);

            File.WriteAllBytes(outputPath, plaintext);
            Console.WriteLine($"File decrypted: {outputPath}");

            // Securely clear plaintext from memory
            Array.Clear(plaintext, 0, plaintext.Length);
        }
    }
}

// Usage
class Program
{
    static void Main()
    {
        byte[] key = new byte[32];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(key);
        }

        FileEncryption.EncryptFile("document.pdf", key);
        FileEncryption.DecryptFile("document.pdf.encrypted", key);
    }
}
```

---

## Encrypting with Additional Authenticated Data

### Using AAD for Metadata

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using IronGcm;

public class MessageWithMetadata
{
    public string UserId { get; set; }
    public DateTime Timestamp { get; set; }
    public string Message { get; set; }
}

public class SecureMessaging
{
    private readonly AesGcmProvider _gcm;

    public SecureMessaging(byte[] key)
    {
        _gcm = new AesGcmProvider(key);
    }

    /// <summary>
    /// Encrypts a message with authenticated metadata (userId and timestamp).
    /// </summary>
    public byte[] EncryptMessage(MessageWithMetadata message)
    {
        // The message is encrypted
        byte[] plaintext = Encoding.UTF8.GetBytes(message.Message);

        // The metadata is authenticated but NOT encrypted
        string metadata = $"{message.UserId}|{message.Timestamp:O}";
        byte[] aad = Encoding.UTF8.GetBytes(metadata);

        byte[] nonce = new byte[12];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(nonce);
        }

        byte[] ciphertext, tag;
        _gcm.Encrypt(nonce, plaintext, out ciphertext, out tag, aad);

        // Package: [metadata length(4)][metadata][nonce(12)][ciphertext][tag(16)]
        using (var ms = new MemoryStream())
        using (var writer = new BinaryWriter(ms))
        {
            writer.Write(aad.Length);
            writer.Write(aad);
            writer.Write(nonce);
            writer.Write(ciphertext);
            writer.Write(tag);
            return ms.ToArray();
        }
    }

    /// <summary>
    /// Decrypts a message and verifies the metadata.
    /// </summary>
    public MessageWithMetadata DecryptMessage(byte[] encrypted)
    {
        using (var ms = new MemoryStream(encrypted))
        using (var reader = new BinaryReader(ms))
        {
            // Read metadata
            int aadLength = reader.ReadInt32();
            byte[] aad = reader.ReadBytes(aadLength);
            string metadata = Encoding.UTF8.GetString(aad);
            string[] parts = metadata.Split('|');

            // Read encryption data
            byte[] nonce = reader.ReadBytes(12);
            long remaining = ms.Length - ms.Position;
            byte[] ciphertext = reader.ReadBytes((int)(remaining - 16));
            byte[] tag = reader.ReadBytes(16);

            // Decrypt with AAD verification
            byte[] plaintext;
            _gcm.Decrypt(nonce, ciphertext, tag, out plaintext, aad);

            return new MessageWithMetadata
            {
                UserId = parts[0],
                Timestamp = DateTime.Parse(parts[1]),
                Message = Encoding.UTF8.GetString(plaintext)
            };
        }
    }

    public void Dispose()
    {
        _gcm?.Dispose();
    }
}

// Usage
class Program
{
    static void Main()
    {
        byte[] key = new byte[32];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(key);
        }

        using (var messaging = new SecureMessaging(key))
        {
            var original = new MessageWithMetadata
            {
                UserId = "user123",
                Timestamp = DateTime.UtcNow,
                Message = "Confidential information"
            };

            byte[] encrypted = messaging.EncryptMessage(original);
            var decrypted = messaging.DecryptMessage(encrypted);

            Console.WriteLine($"User: {decrypted.UserId}");
            Console.WriteLine($"Time: {decrypted.Timestamp}");
            Console.WriteLine($"Message: {decrypted.Message}");
        }
    }
}
```

---

## Key Management

### Secure Key Storage with DPAPI

```csharp
using System;
using System.IO;
using System.Security.Cryptography;

public class KeyManager
{
    private const string KeyFileName = "encryption.key";

    /// <summary>
    /// Generates a new encryption key and stores it securely using DPAPI.
    /// </summary>
    public static byte[] GenerateAndStoreKey(string keyFilePath)
    {
        // Generate random key
        byte[] key = new byte[32];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(key);
        }

        // Protect using DPAPI (Windows Data Protection API)
        byte[] protectedKey = ProtectedData.Protect(
            key,
            null,
            DataProtectionScope.CurrentUser);

        // Save to file
        File.WriteAllBytes(keyFilePath, protectedKey);

        return key;
    }

    /// <summary>
    /// Loads and decrypts the encryption key from file.
    /// </summary>
    public static byte[] LoadKey(string keyFilePath)
    {
        if (!File.Exists(keyFilePath))
            throw new FileNotFoundException("Encryption key file not found", keyFilePath);

        byte[] protectedKey = File.ReadAllBytes(keyFilePath);

        // Unprotect using DPAPI
        byte[] key = ProtectedData.Unprotect(
            protectedKey,
            null,
            DataProtectionScope.CurrentUser);

        return key;
    }
}

// Usage
class Program
{
    static void Main()
    {
        string keyPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "MyApp",
            "encryption.key");

        // First time: generate and store key
        if (!File.Exists(keyPath))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(keyPath));
            KeyManager.GenerateAndStoreKey(keyPath);
            Console.WriteLine("New encryption key generated and stored securely.");
        }

        // Load the key
        byte[] key = KeyManager.LoadKey(keyPath);

        // Use the key
        using (var gcm = new AesGcmProvider(key))
        {
            // ... perform encryption/decryption
        }

        // Clear key from memory
        Array.Clear(key, 0, key.Length);
    }
}
```

---

## Database Integration

### Encrypting Sensitive Database Fields

```csharp
using System;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using IronGcm;

public class SecureUserData
{
    public int UserId { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    public string SensitiveData { get; set; }
}

public class SecureDataRepository : IDisposable
{
    private readonly string _connectionString;
    private readonly AesGcmProvider _gcm;

    public SecureDataRepository(string connectionString, byte[] encryptionKey)
    {
        _connectionString = connectionString;
        _gcm = new AesGcmProvider(encryptionKey);
    }

    public void SaveUser(SecureUserData user)
    {
        // Encrypt sensitive data
        byte[] encryptedData = EncryptField(user.SensitiveData);

        using (var conn = new SqlConnection(_connectionString))
        using (var cmd = new SqlCommand(
            "INSERT INTO Users (Username, Email, EncryptedData) VALUES (@Username, @Email, @Data)",
            conn))
        {
            cmd.Parameters.AddWithValue("@Username", user.Username);
            cmd.Parameters.AddWithValue("@Email", user.Email);
            cmd.Parameters.AddWithValue("@Data", encryptedData);

            conn.Open();
            cmd.ExecuteNonQuery();
        }
    }

    public SecureUserData LoadUser(int userId)
    {
        using (var conn = new SqlConnection(_connectionString))
        using (var cmd = new SqlCommand(
            "SELECT Username, Email, EncryptedData FROM Users WHERE UserId = @UserId",
            conn))
        {
            cmd.Parameters.AddWithValue("@UserId", userId);

            conn.Open();
            using (var reader = cmd.ExecuteReader())
            {
                if (reader.Read())
                {
                    return new SecureUserData
                    {
                        UserId = userId,
                        Username = reader.GetString(0),
                        Email = reader.GetString(1),
                        SensitiveData = DecryptField((byte[])reader["EncryptedData"])
                    };
                }
            }
        }

        return null;
    }

    private byte[] EncryptField(string value)
    {
        if (string.IsNullOrEmpty(value))
            return Array.Empty<byte>();

        byte[] plaintext = Encoding.UTF8.GetBytes(value);
        byte[] nonce = new byte[12];

        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(nonce);
        }

        byte[] ciphertext, tag;
        _gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);

        // Combine for storage
        byte[] result = new byte[12 + ciphertext.Length + 16];
        Buffer.BlockCopy(nonce, 0, result, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, result, 12, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, 12 + ciphertext.Length, 16);

        return result;
    }

    private string DecryptField(byte[] encrypted)
    {
        if (encrypted == null || encrypted.Length == 0)
            return string.Empty;

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

---

## Bulk Operations

### Processing Multiple Messages Efficiently

```csharp
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using IronGcm;

public class BulkEncryption
{
    /// <summary>
    /// Encrypts multiple messages in parallel using a single provider instance (thread-safe).
    /// </summary>
    public static List<EncryptedMessage> EncryptBulk(List<string> messages, byte[] key)
    {
        var results = new List<EncryptedMessage>(messages.Count);
        var lockObj = new object();

        using (var gcm = new AesGcmProvider(key))
        {
            Parallel.ForEach(messages, message =>
            {
                byte[] plaintext = Encoding.UTF8.GetBytes(message);
                byte[] nonce = new byte[12];

                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(nonce);
                }

                byte[] ciphertext, tag;
                gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);

                var encrypted = new EncryptedMessage
                {
                    Nonce = nonce,
                    Ciphertext = ciphertext,
                    Tag = tag
                };

                lock (lockObj)
                {
                    results.Add(encrypted);
                }
            });
        }

        return results;
    }
}

public class EncryptedMessage
{
    public byte[] Nonce { get; set; }
    public byte[] Ciphertext { get; set; }
    public byte[] Tag { get; set; }
}
```

---

## Error Handling

### Robust Error Handling

```csharp
using System;
using System.Security.Cryptography;
using IronGcm;

public class SafeEncryption
{
    public static bool TryEncrypt(
        byte[] key,
        byte[] nonce,
        byte[] plaintext,
        out byte[] ciphertext,
        out byte[] tag,
        out string error)
    {
        ciphertext = null;
        tag = null;
        error = null;

        try
        {
            using (var gcm = new AesGcmProvider(key))
            {
                gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);
                return true;
            }
        }
        catch (ArgumentNullException ex)
        {
            error = $"Invalid argument: {ex.ParamName}";
            return false;
        }
        catch (ArgumentException ex)
        {
            error = $"Invalid key size: {ex.Message}";
            return false;
        }
        catch (CryptographicException ex)
        {
            error = $"Encryption failed: {ex.Message}";
            return false;
        }
        catch (Exception ex)
        {
            error = $"Unexpected error: {ex.Message}";
            return false;
        }
    }

    public static bool TryDecrypt(
        byte[] key,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag,
        out byte[] plaintext,
        out string error)
    {
        plaintext = null;
        error = null;

        try
        {
            using (var gcm = new AesGcmProvider(key))
            {
                gcm.Decrypt(nonce, ciphertext, tag, out plaintext);
                return true;
            }
        }
        catch (CryptographicException ex)
        {
            error = "Authentication failed - data may have been tampered with";
            return false;
        }
        catch (Exception ex)
        {
            error = $"Decryption failed: {ex.Message}";
            return false;
        }
    }
}

// Usage
class Program
{
    static void Main()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[] { 1, 2, 3, 4, 5 };

        byte[] ciphertext, tag;
        string error;

        if (SafeEncryption.TryEncrypt(key, nonce, plaintext, out ciphertext, out tag, out error))
        {
            Console.WriteLine("Encryption successful");

            byte[] decrypted;
            if (SafeEncryption.TryDecrypt(key, nonce, ciphertext, tag, out decrypted, out error))
            {
                Console.WriteLine("Decryption successful");
            }
            else
            {
                Console.WriteLine($"Decryption failed: {error}");
            }
        }
        else
        {
            Console.WriteLine($"Encryption failed: {error}");
        }
    }
}
```

---

## Additional Resources

- See [README.md](README.md) for complete API documentation
- See [GETTING_STARTED.md](GETTING_STARTED.md) for beginner-friendly guide
- Review the test project for more examples
