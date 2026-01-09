using System;
using System.Security.Cryptography;
using System.Text;
using IronGcm;

class TestProgram
{
    static void Main()
    {
        try
        {
            // Test with all zeros (like the failing test)
            byte[] key = new byte[32];
            byte[] nonce = new byte[12];
            byte[] plaintext = Encoding.UTF8.GetBytes("Test");

            Console.WriteLine("Testing with all-zero key and nonce...");
            using (var provider = new AesGcmProvider(key))
            {
                byte[] ciphertext, tag;
                provider.Encrypt(nonce, plaintext, out ciphertext, out tag);
                Console.WriteLine("Encryption succeeded!");
                Console.WriteLine($"Ciphertext: {BitConverter.ToString(ciphertext)}");
                Console.WriteLine($"Tag: {BitConverter.ToString(tag)}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.GetType().Name}");
            Console.WriteLine($"Message: {ex.Message}");
            Console.WriteLine($"Stack: {ex.StackTrace}");
        }

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }
}
