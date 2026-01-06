# Security Best Practices for IronGcm

This document outlines critical security considerations when using IronGcm for AES-GCM encryption in your applications.

## Table of Contents

1. [Nonce Management](#nonce-management)
2. [Key Management](#key-management)
3. [Authentication Tag Validation](#authentication-tag-validation)
4. [Additional Authenticated Data (AAD)](#additional-authenticated-data-aad)
5. [Memory Security](#memory-security)
6. [Common Pitfalls](#common-pitfalls)
7. [Compliance Considerations](#compliance-considerations)

---

## Nonce Management

### The Golden Rule: Never Reuse a Nonce

?? **CRITICAL**: The most important security requirement for GCM is that **you must NEVER reuse a nonce with the same key**.

**Why?** Reusing a nonce with the same key completely breaks the security of AES-GCM:
- Attackers can recover the authentication key
- Attackers can forge valid ciphertexts
- Confidentiality is compromised

### Recommended Nonce Generation

```csharp
// ? GOOD: Random nonce generation
byte[] nonce = new byte[12];
using (var rng = new RNGCryptoServiceProvider())
{
    rng.GetBytes(nonce);
}
```

```csharp
// ? BAD: Reusing the same nonce
byte[] nonce = new byte[12]; // All zeros - NEVER DO THIS
gcm.Encrypt(nonce, plaintext1, out ciphertext1, out tag1);
gcm.Encrypt(nonce, plaintext2, out ciphertext2, out tag2); // SECURITY VIOLATION!
```

### Nonce Size Recommendations

| Nonce Size | Security Implications |
|------------|----------------------|
| **12 bytes (96 bits)** | ? **Recommended** - Optimal performance, supports ~2^32 random nonces before birthday bound |
| 16 bytes (128 bits) | ? Acceptable - Requires additional internal processing |
| 8 bytes (64 bits) | ?? Not recommended - Increased collision risk |

### Nonce Generation Strategies

#### Strategy 1: Random Nonces (Recommended)

```csharp
// Best for most use cases
byte[] nonce = new byte[12];
using (var rng = new RNGCryptoServiceProvider())
{
    rng.GetBytes(nonce);
}
```

**Pros:**
- Simple to implement
- No state to maintain
- Thread-safe

**Cons:**
- Limited to ~2^32 encryptions per key (birthday bound)
- Need to store/transmit nonce with ciphertext

#### Strategy 2: Counter-Based Nonces

```csharp
public class CounterNonceGenerator
{
    private long _counter = 0;
    private readonly object _lock = new object();
    private readonly byte[] _randomPrefix = new byte[4];

    public CounterNonceGenerator()
    {
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(_randomPrefix);
        }
    }

    public byte[] GetNextNonce()
    {
        lock (_lock)
        {
            byte[] nonce = new byte[12];
            Buffer.BlockCopy(_randomPrefix, 0, nonce, 0, 4);
            BitConverter.GetBytes(_counter++).CopyTo(nonce, 4);
            return nonce;
        }
    }
}
```

**Pros:**
- Deterministic - easier to detect reuse
- Can support more encryptions per key
- Efficient

**Cons:**
- Must maintain state
- Risk if counter state is lost or reset
- More complex implementation

---

## Key Management

### Key Generation

**Always use cryptographically secure random number generators:**

```csharp
// ? GOOD: Secure key generation
byte[] key = new byte[32]; // AES-256
using (var rng = new RNGCryptoServiceProvider())
{
    rng.GetBytes(key);
}
```

```csharp
// ? BAD: Weak or predictable keys
byte[] key = Encoding.UTF8.GetBytes("my-secret-key-123"); // NEVER DO THIS
byte[] key = new byte[32]; // All zeros - NEVER DO THIS
```

### Key Size Selection

| Key Size | AES Variant | Security Level | Recommendation |
|----------|-------------|----------------|----------------|
| 16 bytes | AES-128 | 128-bit | Acceptable for most use cases |
| 24 bytes | AES-192 | 192-bit | Government/military applications |
| **32 bytes** | **AES-256** | **256-bit** | **? Recommended for new applications** |

### Secure Key Storage

#### Option 1: Windows DPAPI (Recommended for Desktop Applications)

```csharp
using System.Security.Cryptography;

public class SecureKeyStorage
{
    public static void SaveKey(byte[] key, string filePath)
    {
        // Encrypt key with current user's credentials
        byte[] protectedKey = ProtectedData.Protect(
            key,
            null,
            DataProtectionScope.CurrentUser);

        File.WriteAllBytes(filePath, protectedKey);
    }

    public static byte[] LoadKey(string filePath)
    {
        byte[] protectedKey = File.ReadAllBytes(filePath);
        
        return ProtectedData.Unprotect(
            protectedKey,
            null,
            DataProtectionScope.CurrentUser);
    }
}
```

#### Option 2: Azure Key Vault (Recommended for Cloud Applications)

```csharp
// Conceptual example - requires Azure SDK
public async Task<byte[]> GetKeyFromVault(string vaultUrl, string keyName)
{
    var client = new SecretClient(new Uri(vaultUrl), new DefaultAzureCredential());
    KeyVaultSecret secret = await client.GetSecretAsync(keyName);
    return Convert.FromBase64String(secret.Value);
}
```

#### Option 3: Hardware Security Module (Recommended for Enterprise)

Consult your HSM vendor's documentation for integration guidance.

### Key Rotation

Implement periodic key rotation to limit the impact of key compromise:

```csharp
public class KeyRotationManager
{
    private readonly Dictionary<int, byte[]> _keyVersions = new Dictionary<int, byte[]>();
    private int _currentKeyVersion = 1;

    public byte[] GetCurrentKey()
    {
        return _keyVersions[_currentKeyVersion];
    }

    public void RotateKey()
    {
        byte[] newKey = new byte[32];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(newKey);
        }

        _currentKeyVersion++;
        _keyVersions[_currentKeyVersion] = newKey;

        // Keep old keys for decrypting old data
        // Remove old keys after re-encryption or retention period
    }

    public byte[] GetKey(int version)
    {
        return _keyVersions[version];
    }
}
```

### Key Lifecycle Best Practices

1. **Generation**: Use cryptographically secure RNGs
2. **Storage**: Use secure key storage mechanisms (DPAPI, Key Vault, HSM)
3. **Distribution**: Use secure channels (TLS, secure key exchange protocols)
4. **Usage**: Implement access controls and audit logging
5. **Rotation**: Rotate keys periodically (e.g., annually or after certain volume)
6. **Destruction**: Securely overwrite key material when no longer needed

---

## Authentication Tag Validation

### Always Validate Before Using Data

```csharp
try
{
    byte[] plaintext;
    gcm.Decrypt(nonce, ciphertext, tag, out plaintext);
    
    // ? Safe to use plaintext here - authentication succeeded
    ProcessData(plaintext);
}
catch (CryptographicException ex)
{
    // ? Authentication failed - DO NOT use any data
    LogSecurityEvent("Authentication failure", ex);
    throw; // Or handle appropriately
}
```

### What Tag Mismatch Means

When you receive a `CryptographicException` with "Authentication tag mismatch":

- **The data has been modified** (intentionally or accidentally)
- **The wrong key is being used**
- **The wrong nonce or AAD is being used**
- **Data corruption occurred during storage/transmission**

**Never use the decrypted data** - it cannot be trusted.

### Tag Size

IronGcm uses a 128-bit (16-byte) authentication tag, which is the recommended size for GCM:

- Provides strong authentication guarantees
- Probability of forgery: ~2^-128 (effectively impossible)
- Compliant with NIST recommendations

---

## Additional Authenticated Data (AAD)

### When to Use AAD

Use AAD when you have metadata that needs to be authenticated but not encrypted:

```csharp
public class EncryptedMessage
{
    public string UserId { get; set; }        // Authenticate but don't encrypt
    public DateTime Timestamp { get; set; }   // Authenticate but don't encrypt
    public byte[] EncryptedContent { get; set; } // Encrypt and authenticate
}

// Example usage
byte[] aad = Encoding.UTF8.GetBytes($"{userId}|{timestamp:O}");
gcm.Encrypt(nonce, plaintext, out ciphertext, out tag, aad);
```

### AAD Must Match Exactly

```csharp
// Encryption
byte[] aad = Encoding.UTF8.GetBytes("metadata");
gcm.Encrypt(nonce, plaintext, out ciphertext, out tag, aad);

// Decryption - AAD must be EXACTLY the same
byte[] sameAad = Encoding.UTF8.GetBytes("metadata");
gcm.Decrypt(nonce, ciphertext, tag, out decrypted, sameAad); // ? Works

// Different AAD will fail
byte[] differentAad = Encoding.UTF8.GetBytes("different");
gcm.Decrypt(nonce, ciphertext, tag, out decrypted, differentAad); // ? Throws exception
```

### AAD Best Practices

1. **Include Context**: User ID, session ID, timestamp, etc.
2. **Be Consistent**: Use the same encoding and format
3. **Document Format**: Clearly document AAD structure
4. **Versioning**: Consider including a version number in AAD

---

## Memory Security

### Clearing Sensitive Data

```csharp
public void EncryptSensitiveData(byte[] key, byte[] plaintext)
{
    try
    {
        using (var gcm = new AesGcmProvider(key))
        {
            // ... encryption logic
        }
    }
    finally
    {
        // Clear sensitive data from memory
        if (key != null)
            Array.Clear(key, 0, key.Length);
        
        if (plaintext != null)
            Array.Clear(plaintext, 0, plaintext.Length);
    }
}
```

### Minimize Key Exposure

```csharp
// ? BAD: Key lives in memory for entire application lifetime
public class BadExample
{
    private static byte[] _globalKey; // Exposed for too long
}

// ? GOOD: Load key only when needed
public class GoodExample
{
    public void ProcessData(string data)
    {
        byte[] key = LoadKeySecurely();
        try
        {
            using (var gcm = new AesGcmProvider(key))
            {
                // Use gcm
            }
        }
        finally
        {
            Array.Clear(key, 0, key.Length);
        }
    }
}
```

---

## Common Pitfalls

### Pitfall 1: Reusing Nonces

```csharp
// ? WRONG
byte[] nonce = new byte[12];
for (int i = 0; i < 100; i++)
{
    gcm.Encrypt(nonce, plaintexts[i], out ciphertexts[i], out tags[i]);
}
```

```csharp
// ? CORRECT
for (int i = 0; i < 100; i++)
{
    byte[] nonce = new byte[12];
    using (var rng = new RNGCryptoServiceProvider())
    {
        rng.GetBytes(nonce);
    }
    gcm.Encrypt(nonce, plaintexts[i], out ciphertexts[i], out tags[i]);
}
```

### Pitfall 2: Not Storing Nonce with Ciphertext

```csharp
// ? WRONG: Nonce not saved
gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);
SaveToDatabase(ciphertext, tag); // Where's the nonce?

// ? CORRECT: Save all components
gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);
byte[] combined = CombineNonceCiphertextTag(nonce, ciphertext, tag);
SaveToDatabase(combined);
```

### Pitfall 3: Using Weak Keys

```csharp
// ? WRONG: Deriving key from password without proper KDF
byte[] key = Encoding.UTF8.GetBytes(password).Take(32).ToArray();

// ? CORRECT: Use PBKDF2 or similar
using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, 100000))
{
    byte[] key = deriveBytes.GetBytes(32);
}
```

### Pitfall 4: Ignoring Authentication Failures

```csharp
// ? WRONG: Using data despite authentication failure
try
{
    gcm.Decrypt(nonce, ciphertext, tag, out plaintext);
}
catch (CryptographicException)
{
    plaintext = new byte[0]; // DON'T USE ANY DATA!
}
ProcessData(plaintext); // DANGEROUS!

// ? CORRECT: Properly handle authentication failure
try
{
    gcm.Decrypt(nonce, ciphertext, tag, out plaintext);
    ProcessData(plaintext);
}
catch (CryptographicException ex)
{
    LogSecurityIncident("Possible tampering detected", ex);
    throw;
}
```

### Pitfall 5: Not Disposing Provider

```csharp
// ? WRONG: Resource leak
var gcm = new AesGcmProvider(key);
gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);
// Provider not disposed - handles leak

// ? CORRECT: Use 'using' statement
using (var gcm = new AesGcmProvider(key))
{
    gcm.Encrypt(nonce, plaintext, out ciphertext, out tag);
}
```

---

## Compliance Considerations

### NIST Guidelines

IronGcm follows NIST SP 800-38D recommendations:
- ? Uses approved key sizes (128, 192, 256 bits)
- ? Uses recommended tag size (128 bits)
- ? Supports recommended nonce size (96 bits)

### FIPS 140-2/3

Windows BCrypt API used by IronGcm can operate in FIPS mode:
- Windows Server: Enable FIPS policy
- Cryptographic operations will use FIPS-validated implementations

### GDPR and Data Protection

When handling personal data:
1. **Encryption at Rest**: Use IronGcm to encrypt sensitive fields
2. **Key Access Controls**: Implement proper key access logging
3. **Data Minimization**: Only encrypt data that needs protection
4. **Right to Erasure**: Implement secure key destruction

### Industry-Specific Requirements

- **Healthcare (HIPAA)**: AES-256 encryption recommended
- **Finance (PCI DSS)**: Strong encryption required for cardholder data
- **Government**: May require FIPS 140-2 validated implementations

---

## Security Checklist

Before deploying IronGcm in production, verify:

- [ ] Keys are generated using RNGCryptoServiceProvider
- [ ] Keys are 32 bytes (AES-256) for new applications
- [ ] Keys are stored securely (DPAPI, Key Vault, or HSM)
- [ ] New random nonce generated for every encryption
- [ ] Nonce is never reused with the same key
- [ ] Nonce is stored/transmitted with ciphertext and tag
- [ ] Authentication tag failures are properly handled
- [ ] Sensitive data is cleared from memory after use
- [ ] Provider is disposed after use (using statement)
- [ ] Error handling does not expose sensitive information
- [ ] Key rotation policy is implemented
- [ ] Security logging is enabled for failures
- [ ] Code has been reviewed by security team
- [ ] Compliance requirements are met

---

## Additional Resources

- [NIST SP 800-38D: GCM Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [NIST Guidelines for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Windows BCrypt API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/)

---

## Reporting Security Issues

If you discover a security vulnerability in IronGcm, please report it responsibly:

[Specify your security contact/process here]

---

**Remember**: Cryptography is easy to get wrong. When in doubt, consult with a security professional.
