using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Configuration;
using System.Collections;


namespace AES_Encryption
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0) 
            {
                Console.Write("Please specify if you want to encrypt or decrypt the payload by adding as first argument [enc|dec]\n");
                Console.ReadLine();
                System.Environment.Exit(404);
            }

            string firstArg = args[0].ToLower(); // Convert to lowercase for case-insensitive


            if (firstArg == "enc")
            {
                // Handle encryption logic
                Console.WriteLine("Encrypting...");
                Encrypt(args[1], args[2], args[3], args[4]);
            }
            else if (firstArg == "dec")
            {
                // Handle decryption logic
                Console.WriteLine("Decrypting...");
                Decrypt(args[1], args[2], args[3], args[4]);
            }
            else
            {
                Console.WriteLine($"Error: Invalid argument '{firstArg}'. Please specify 'enc' or 'dec'.");
                Environment.Exit(1); // Exit with an error code
            }
            Console.ReadLine();
        }

        static void Encrypt(string payloadPath, string outputPath, string keyPath, string IVPath)
        {
            Console.Write("Starting to read payload file.\n");
            // Define paths of files.
            // string pathRead = ".\\payload.txt";
            // string pathWrite = ".\\payload_enc.txt";            

            // Check if payload file exists and if not raise exception.
            if (!File.Exists(payloadPath))
            {
                throw new FileNotFoundException($"File not found: {payloadPath}");
            }

            // Read content of a file.
            string readContents;
            using (StreamReader streamReader = new StreamReader(payloadPath, Encoding.UTF8))
            {
                readContents = streamReader.ReadToEnd();
            }
            // Define postions of data.
            int indStart = readContents.IndexOf('{') + 1;
            int indEnd = readContents.IndexOf('}');
            int length = indEnd - indStart;
            // Extract data, remove whitespaces and split it on commans.
            string extracted = readContents.Substring(indStart, length);
            string cleaned = RemoveWhitespaces(extracted);
            //List<string> hexes = cleaned.Split(',').ToList<string>();
            string[] hexes = cleaned.Split(',');
            Console.Write("Print content of the file.\n");
            // Declare new temporal byte array that will store encoded payload.
            byte[] payloadBytes = new byte[hexes.Length];
            for (int i = 0; i < hexes.Length; i++)
            {
                // Iterate over payload, XOR it and append to output.
                payloadBytes[i] = Convert.ToByte(hexes[i].Substring(2, 2), 16);
            }

            byte[] key;
            if (File.Exists(keyPath))
            {
                Console.WriteLine($"File {keyPath} exists. Reading its content.");
                // Read content of a file.
                string keyFile;
                using (StreamReader streamReader = new StreamReader(keyPath, Encoding.UTF8))
                {
                    keyFile = streamReader.ReadToEnd();
                }
                
                key = Convert.FromBase64String(keyFile);
                if (key.Length != 32)
                {
                    throw new ArgumentException("Encryption key must 256 bits long.");
                }
            }
            else
            {
                Console.WriteLine($"File {keyPath} does not exist. Creating a new key.");
                // Create random key
                key = CreateRandomVec(256);
                // Save random key
                string base64Key = Convert.ToBase64String(key);
                // Write output to file
                StreamWriter streamKey = new StreamWriter(keyPath);
                streamKey.Write(base64Key);
                streamKey.Close();

            }

            byte[] IV;
            if (File.Exists(IVPath))
            {
                Console.WriteLine($"File {IVPath} exists. Reading its content.");
                // Read content of a file.
                string IVFile;
                using (StreamReader streamReader = new StreamReader(IVPath, Encoding.UTF8))
                {
                    IVFile = streamReader.ReadToEnd();
                }
                IV = Convert.FromBase64String(IVFile);
                if (IV.Length != 16)
                {
                    throw new ArgumentException("Initial vector must 128 bits long.");
                }
            }
            else
            {
                Console.WriteLine($"File {IVPath} does not exist. Creating a new file.");
                // Create random vector
                IV = CreateRandomVec(128);
                // Save random key
                string base64IV = Convert.ToBase64String(IV);
                // Write output to file
                StreamWriter streamIV = new StreamWriter(IVPath);
                streamIV.Write(base64IV);
                streamIV.Close();
            }


            // Encrypt the data
            byte[] encryptedData = EncryptAes(payloadBytes, key, IV);
            // Decrypt the data (for demonstration purposes)
            // byte[] decryptedData = DecryptAes(encryptedData, key, iv);

            string output = Convert.ToBase64String(encryptedData);
            Console.WriteLine($"Encoded form is:\n{output}");

            if (File.Exists(outputPath))
            {
                Console.WriteLine($"File {outputPath} already exists. Removing it.");
                File.Delete(outputPath);
            }

            // Write output to file
            Console.WriteLine($"Writing encoded payload to \"{outputPath}\".");
            StreamWriter streamW = new StreamWriter(outputPath);
            streamW.Write(output);
            streamW.Close();
        }

        static void Decrypt(string payloadPath, string outputPath, string keyPath, string IVPath)
        {
            Console.Write("Starting to read payload file.\n");
            // Define paths of files.
            // string pathRead = ".\\payload.txt";
            // string pathWrite = ".\\payload_enc.txt";            

            // Check if payload file exists and if not raise exception.
            if (!File.Exists(payloadPath))
            {
                throw new FileNotFoundException($"File not found: {payloadPath}");
            }

            // Read content of a file.
            string readContents;
            using (StreamReader streamReader = new StreamReader(payloadPath, Encoding.UTF8))
            {
                readContents = streamReader.ReadToEnd();
            }
            // Define postions of data.
            Console.WriteLine($"Encypted payload is {readContents}.");
            byte[] payloadBytes = Convert.FromBase64String(readContents);

            byte[] key;
            if (File.Exists(keyPath))
            {
                Console.WriteLine($"File {keyPath} exists. Reading its content.");
                // Read content of a file.
                string keyFile;
                using (StreamReader streamReader = new StreamReader(keyPath, Encoding.UTF8))
                {
                    keyFile = streamReader.ReadToEnd();
                }

                key = Convert.FromBase64String(keyFile);
                if (key.Length != 32)
                {
                    throw new ArgumentException("Encryption key must 256 bits long.");
                }
            }
            else
            {
                throw new ArgumentException("Encryption key does not exist.");
            }

            byte[] IV;
            if (File.Exists(IVPath))
            {
                Console.WriteLine($"File {IVPath} exists. Reading its content.");
                // Read content of a file.
                string IVFile;
                using (StreamReader streamReader = new StreamReader(IVPath, Encoding.UTF8))
                {
                    IVFile = streamReader.ReadToEnd();
                }
                IV = Convert.FromBase64String(IVFile);
                if (IV.Length != 16)
                {
                    throw new ArgumentException("Initial vector must 128 bits long.");
                }
            }
            else
            {
                throw new ArgumentException("IV does not exist.");
            }


            // Decrypt the data (for demonstration purposes)
            byte[] decryptedData = DecryptAes(payloadBytes, key, IV);
            // Decrypt the data (for demonstration purposes)
            // byte[] decryptedData = DecryptAes(encryptedData, key, iv);

            StringBuilder output = new StringBuilder();
            for (int i = 0; i < decryptedData.Length; i++)
            {
                // Iterate over payload, XOR it and append to output.
                output.AppendFormat("0x{0:x2},", decryptedData[i]);
            }
            // Remove final coma.
            output.Length -= 1;
            // Append closing bracket.
            output.Append("};");
            // Append buf declaration and opening bracket.
            output.Insert(0, $"byte[] buf = new byte[{decryptedData.Length}] {{");
            Console.WriteLine($"Decrypted form is:\n{output}");


            if (File.Exists(outputPath))
            {
                Console.WriteLine($"File {outputPath} already exists. Removing it.");
                File.Delete(outputPath);
            }

            // Write output to file
            Console.WriteLine($"Writing encoded payload to \"{outputPath}\".");
            StreamWriter streamW = new StreamWriter(outputPath);
            streamW.Write(output);
            streamW.Close();
        }

        static byte[] CreateRandomVec(int bitsCount)
        {
            int byteCount = bitsCount/8;
            Random rnd = new Random();
            byte[] byteArray = new byte[byteCount];
            rnd.NextBytes(byteArray);
            return byteArray;
        }
        static byte[] EncryptAes(byte[] input, byte[] key, byte[] iv)
        {
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(input, 0, input.Length);
                    }
                    return ms.ToArray();
                }
            }
        }

        static byte[] DecryptAes(byte[] input, byte[] key, byte[] iv)
        {
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aesAlg.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(input, 0, input.Length);
                    }
                    return ms.ToArray();
                }
            }
        }
        public static string RemoveWhitespaces(string source)
        {
            // Function to remove whitespaces.
            return Regex.Replace(source, @"\s", string.Empty);
        }
    }
}
