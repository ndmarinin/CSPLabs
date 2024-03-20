using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class ProgramB
{
    static RSACryptoServiceProvider rsaProviderB = new RSACryptoServiceProvider();
    static AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
    static RSACryptoServiceProvider signatureProviderB = new RSACryptoServiceProvider(1024);

    static TcpListener server = new TcpListener(IPAddress.Parse("127.0.0.1"), 1234);


    static async Task Main(string[] args)
    {
        server.Start();

        // Участник Б - создание ключевой пары шифрования
        string publicKeyB = ExportPublicKey(rsaProviderB);

        Console.WriteLine("B: Ожидание подключение клиента");
        TcpClient client = server.AcceptTcpClient();
        NetworkStream stream = client.GetStream();
        // Участник Б - отправка открытого ключа шифрования
        byte[] publicKeyBBytes = Encoding.ASCII.GetBytes(publicKeyB);
        stream.Write(publicKeyBBytes, 0, publicKeyBBytes.Length);
        Console.WriteLine($"B: Отправка PublicKey-B{publicKeyB}");




        byte[] encryptedSessionKey = new byte[128];
        stream.Read(encryptedSessionKey, 0, encryptedSessionKey.Length);
        Console.WriteLine($"B: Получили зашифрованный ключ {BitConverter.ToString(encryptedSessionKey)}");

        byte[] signature = new byte[128];
        stream.Read(signature, 0, signature.Length);
        Console.WriteLine($"B: Получили подпись {BitConverter.ToString(signature)}");

        // Участник Б - импорт открытого ключа проверки участника А
        byte[] receivedBytes1 = new byte[243];
        stream.Read(receivedBytes1, 0, receivedBytes1.Length);
        string publicKeyA = Encoding.ASCII.GetString(receivedBytes1);
        Console.WriteLine($"B: Получили PublicKey-A {publicKeyA}");

        byte[] decryptSessionKey = rsaProviderB.Decrypt(encryptedSessionKey, false);
        signatureProviderB.FromXmlString(publicKeyA);
        bool verify = signatureProviderB.VerifyData(encryptedSessionKey, new SHA256CryptoServiceProvider(), signature);
        Console.WriteLine($"B: Session key {BitConverter.ToString(decryptSessionKey)}");
        Console.WriteLine($"B: Signature {verify}");

        aesProvider.Key = decryptSessionKey;

        byte[] receivedEncryptedMessage = new byte[16];
        stream.Read(receivedEncryptedMessage, 0, receivedEncryptedMessage.Length);

        byte[] receivedMessageSign = new byte[128];
        stream.Read(receivedMessageSign, 0, receivedMessageSign.Length);

        byte[] iv = new byte[16];
        Array.Clear(iv, 0, iv.Length);

        string decryptedMessage = DecryptStringFromBytes_Aes(receivedEncryptedMessage, decryptSessionKey, iv);
        Console.WriteLine($"B: Get message {decryptedMessage}");
        bool verifyMessage = signatureProviderB.VerifyData(receivedEncryptedMessage, new SHA256CryptoServiceProvider(), receivedMessageSign);
        Console.WriteLine($"B: Signature of message {verifyMessage}");


        Console.ReadLine();
        stream.Close();
        server.Stop();
    }

    // Метод для генерации сессионного ключа
    static byte[] GenerateSessionKey()
    {
        aesProvider.GenerateKey();
        return aesProvider.Key;
    }

    // Метод для экспорта открытого ключа
    static string ExportPublicKey(RSACryptoServiceProvider provider)
    {
        return provider.ToXmlString(false);
    }

    // Метод для импорта открытого ключа
    static void ImportPublicKey(string publicKey, RSACryptoServiceProvider provider)
    {
        provider.FromXmlString(publicKey);
    }

    static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
    {
        // Check arguments.
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException("plainText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");
        byte[] encrypted;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        // Return the encrypted bytes from the memory stream.
        return encrypted;
    }

    static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
    {
        // Check arguments.
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException("cipherText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");

        // Declare the string used to hold
        // the decrypted text.
        string plaintext = null;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        return plaintext;
    }

}
