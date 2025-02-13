using System;
using System.IO;

public class RC4
{
    private byte[] S = new byte[256];
    private byte[] T = new byte[256];

    public void Init(byte[] key)
    {
        for (int i = 0; i < 256; i++)
        {
            S[i] = (byte)i;
            T[i] = key[i % key.Length];
        }

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + S[i] + T[i]) % 256;
            byte temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }
    }

    public byte[] Process(byte[] data)
    {
        byte[] result = new byte[data.Length];
        int i = 0, j = 0;

        for (int k = 0; k < data.Length; k++)
        {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            byte temp = S[i];
            S[i] = S[j];
            S[j] = temp;

            int t = (S[i] + S[j]) % 256;
            result[k] = (byte)(data[k] ^ S[t]);
        }

        return result;
    }
}

class Program
{
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: RC4RawFileEncoder.exe <raw_file.bin>");
            Console.WriteLine("[#] Hit ENTER to exit...");
            Console.ReadLine();
            return;
        }

        string fileName = args[0];

        Console.WriteLine("[*] RC4 Raw File Encoder by Razz");
        Console.WriteLine("[*] Your file: " + fileName);

        byte[] shellcode = File.ReadAllBytes(fileName);
        string inputFileName = Path.GetFileName(fileName);
        string outputFileName = $"encoded_{inputFileName}";

        // Key
        byte[] key = new byte[16] { 0x31, 0x37, 0x30, 0x31, 0x32, 0x37, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x63, 0x31 };

        // Encrypt
        RC4 rc4 = new RC4();
        rc4.Init(key);

        byte[] encryptedData = rc4.Process(shellcode);
        File.WriteAllBytes(outputFileName, encryptedData);

        // DEBUG - Decipher
        /* rc4.Init(key); 
        byte[] decryptedData = rc4.Process(encryptedData);
        File.WriteAllBytes($"decrypted_{inputFileName}", decryptedData); */

        Console.WriteLine("[+] Done!");
        Console.WriteLine("[#] Hit ENTER to exit...");
        Console.ReadLine();
    }
}