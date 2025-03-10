using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AdvancedCryptoConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "Gelişmiş Kripto Uygulaması";
            Console.WriteLine("=====================================");
            Console.WriteLine("    Gelişmiş Kripto Uygulamasına Hoş Geldiniz!");
            Console.WriteLine("=====================================");

            while (true)
            {
                DisplayMenu();
                string choice = Console.ReadLine();

                try
                {
                    switch (choice)
                    {
                        case "1":
                            EncryptTextWithAES();
                            break;
                        case "2":
                            DecryptTextWithAES();
                            break;
                        case "3":
                            EncryptFileWithAES();
                            break;
                        case "4":
                            DecryptFileWithAES();
                            break;
                        case "5":
                            GenerateRSAKeys();
                            break;
                        case "6":
                            EncryptTextWithRSA();
                            break;
                        case "7":
                            DecryptTextWithRSA();
                            break;
                        case "8":
                            Console.WriteLine("Çıkılıyor...");
                            return;
                        default:
                            Console.WriteLine("Geçersiz seçim! 1-8 arasında bir sayı girin.");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Hata: {ex.Message}");
                }

                Console.WriteLine("\nDevam etmek için bir tuşa basın...");
                Console.ReadKey();
                Console.Clear();
            }
        }

        static void DisplayMenu()
        {
            Console.WriteLine("\n=== Menü ===");
            Console.WriteLine("1. Metni AES ile Şifrele");
            Console.WriteLine("2. AES ile Şifrelenmiş Metni Çöz");
            Console.WriteLine("3. Dosyayı AES ile Şifrele");
            Console.WriteLine("4. AES ile Şifrelenmiş Dosyayı Çöz");
            Console.WriteLine("5. RSA Anahtar Çifti Oluştur");
            Console.WriteLine("6. Metni RSA ile Şifrele");
            Console.WriteLine("7. RSA ile Şifrelenmiş Metni Çöz");
            Console.WriteLine("8. Çıkış");
            Console.Write("Seçiminizi yapın (1-8): ");
        }

        // AES ile metin şifreleme
        static void EncryptTextWithAES()
        {
            Console.WriteLine("Şifrelenecek metni girin:");
            string plainText = Console.ReadLine();
            Console.WriteLine("Parolayı girin (en az 8 karakter):");
            string password = Console.ReadLine();

            if (string.IsNullOrEmpty(plainText) || string.IsNullOrEmpty(password) || password.Length < 8)
            {
                Console.WriteLine("Metin veya parola geçersiz!");
                return;
            }

            byte[] key = GenerateKeyFromPassword(password);
            string encrypted = EncryptAES(plainText, key);
            Console.WriteLine($"Şifrelenmiş metin: {encrypted}");
        }

        // AES ile metin çözme
        static void DecryptTextWithAES()
        {
            Console.WriteLine("Çözülecek şifreli metni girin (Base64):");
            string cipherText = Console.ReadLine();
            Console.WriteLine("Parolayı girin:");
            string password = Console.ReadLine();

            if (string.IsNullOrEmpty(cipherText) || string.IsNullOrEmpty(password))
            {
                Console.WriteLine("Metin veya parola geçersiz!");
                return;
            }

            byte[] key = GenerateKeyFromPassword(password);
            string decrypted = DecryptAES(cipherText, key);
            Console.WriteLine($"Çözülmüş metin: {decrypted}");
        }

        // AES ile dosya şifreleme
        static void EncryptFileWithAES()
        {
            Console.WriteLine("Şifrelenecek dosyanın tam yolunu girin:");
            string inputFile = Console.ReadLine();
            Console.WriteLine("Parolayı girin (en az 8 karakter):");
            string password = Console.ReadLine();

            if (!File.Exists(inputFile) || string.IsNullOrEmpty(password) || password.Length < 8)
            {
                Console.WriteLine("Dosya bulunamadı veya parola geçersiz!");
                return;
            }

            byte[] key = GenerateKeyFromPassword(password);
            string outputFile = inputFile + ".enc";
            EncryptFileAES(inputFile, outputFile, key);
            Console.WriteLine($"Dosya şifrelendi: {outputFile}");
        }

        // AES ile dosya çözme
        static void DecryptFileWithAES()
        {
            Console.WriteLine("Çözülecek şifreli dosyanın tam yolunu girin:");
            string inputFile = Console.ReadLine();
            Console.WriteLine("Parolayı girin:");
            string password = Console.ReadLine();

            if (!File.Exists(inputFile) || string.IsNullOrEmpty(password))
            {
                Console.WriteLine("Dosya bulunamadı veya parola geçersiz!");
                return;
            }

            byte[] key = GenerateKeyFromPassword(password);
            string outputFile = Path.Combine(Path.GetDirectoryName(inputFile),
                Path.GetFileNameWithoutExtension(inputFile) + "_decrypted" + Path.GetExtension(inputFile));
            DecryptFileAES(inputFile, outputFile, key);
            Console.WriteLine($"Dosya çözüldü: {outputFile}");
        }

        // RSA anahtar çifti oluşturma
        static void GenerateRSAKeys()
        {
            using (RSA rsa = RSA.Create(2048)) // 2048-bit anahtar
            {
                string publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                string privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

                File.WriteAllText("publicKey.txt", publicKey);
                File.WriteAllText("privateKey.txt", privateKey);
                Console.WriteLine("RSA anahtar çifti oluşturuldu: publicKey.txt ve privateKey.txt");
            }
        }

        // RSA ile metin şifreleme
        static void EncryptTextWithRSA()
        {
            Console.WriteLine("Şifrelenecek metni girin:");
            string plainText = Console.ReadLine();
            Console.WriteLine("Public key dosyasının yolunu girin (örn: publicKey.txt):");
            string publicKeyFile = Console.ReadLine();

            if (!File.Exists(publicKeyFile) || string.IsNullOrEmpty(plainText))
            {
                Console.WriteLine("Dosya bulunamadı veya metin geçersiz!");
                return;
            }

            string publicKey = File.ReadAllText(publicKeyFile);
            string encrypted = EncryptRSA(plainText, publicKey);
            Console.WriteLine($"Şifrelenmiş metin: {encrypted}");
        }

        // RSA ile metin çözme
        static void DecryptTextWithRSA()
        {
            Console.WriteLine("Çözülecek şifreli metni girin (Base64):");
            string cipherText = Console.ReadLine();
            Console.WriteLine("Private key dosyasının yolunu girin (örn: privateKey.txt):");
            string privateKeyFile = Console.ReadLine();

            if (!File.Exists(privateKeyFile) || string.IsNullOrEmpty(cipherText))
            {
                Console.WriteLine("Dosya bulunamadı veya metin geçersiz!");
                return;
            }

            string privateKey = File.ReadAllText(privateKeyFile);
            string decrypted = DecryptRSA(cipherText, privateKey);
            Console.WriteLine($"Çözülmüş metin: {decrypted}");
        }

        // Paroladan AES anahtarı türetme (PBKDF2)
        static byte[] GenerateKeyFromPassword(string password)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes("Salt1234"), 10000, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(32); // 256-bit anahtar
            }
        }

        // AES şifreleme fonksiyonu
        static string EncryptAES(string plainText, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                byte[] iv = aes.IV;

                using (var ms = new MemoryStream())
                {
                    ms.Write(iv, 0, iv.Length);
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        // AES çözme fonksiyonu
        static string DecryptAES(string cipherText, byte[] key)
        {
            byte[] fullCipher = Convert.FromBase64String(cipherText);
            using (Aes aes = Aes.Create())
            {
                byte[] iv = new byte[aes.BlockSize / 8];
                Array.Copy(fullCipher, 0, iv, 0, iv.Length);
                byte[] cipherBytes = new byte[fullCipher.Length - iv.Length];
                Array.Copy(fullCipher, iv.Length, cipherBytes, 0, cipherBytes.Length);

                aes.Key = key;
                aes.IV = iv;

                using (var ms = new MemoryStream(cipherBytes))
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }

        // AES ile dosya şifreleme
        static void EncryptFileAES(string inputFile, string outputFile, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                byte[] iv = aes.IV;

                using (var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    fsOutput.Write(iv, 0, iv.Length);
                    using (var cs = new CryptoStream(fsOutput, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        fsInput.CopyTo(cs);
                    }
                }
            }
        }

        // AES ile dosya çözme
        static void DecryptFileAES(string inputFile, string outputFile, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                byte[] iv = new byte[aes.BlockSize / 8];
                using (var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                {
                    fsInput.Read(iv, 0, iv.Length);
                    aes.Key = key;
                    aes.IV = iv;

                    using (var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                    using (var cs = new CryptoStream(fsOutput, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        fsInput.CopyTo(cs);
                    }
                }
            }
        }

        // RSA ile şifreleme
        static string EncryptRSA(string plainText, string publicKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
                byte[] data = Encoding.UTF8.GetBytes(plainText);
                byte[] encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
                return Convert.ToBase64String(encrypted);
            }
        }

        // RSA ile çözme
        static string DecryptRSA(string cipherText, string privateKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                byte[] decrypted = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(decrypted);
            }
        }
    }
}
