using System;
using System.IO;

namespace XORPayloadEncoder
{
    internal class Program
    {
        public static void XorByInputKeyEnc(byte[] shellcode, int shellcodeSize, byte[] key, int keySize)
        {
            for (int i = 0, j = 0; i < shellcodeSize; i++, j++)
            {
                if (j >= keySize)
                {
                    j = 0;
                }
                shellcode[i] ^= key[j];
            }
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: XORRawFileEncoder.exe <raw_file.bin>");
                Console.WriteLine("[#] Hit ENTER to exit...");
                Console.ReadLine();
                return;
            }

            string fileName = args[0];

            Console.WriteLine("[*] XOR Raw File Encoder by Razz");
            Console.WriteLine("[*] Your file: " + fileName);

            //provide your own 16-byte or even longer key to encode the payload
            byte[] key = new byte[16] { 0x31, 0x37, 0x30, 0x31, 0x32, 0x37, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x63, 0x31 };

            byte[] shellcode = File.ReadAllBytes(fileName);
            string inputFileName = Path.GetFileName(fileName);
            string outputFileName = $"encoded_{inputFileName}";

            Console.WriteLine("[*] The size of array is: " + shellcode.Length);
            Console.WriteLine("[#] Encoding with key saved in key variable.");

            XorByInputKeyEnc(shellcode, shellcode.Length, key, key.Length);

            File.WriteAllBytes(outputFileName, shellcode);
            Console.WriteLine("[+] Done!");

            Console.WriteLine("[#] Hit ENTER to exit...");
            Console.ReadLine();
        }
    }
}
