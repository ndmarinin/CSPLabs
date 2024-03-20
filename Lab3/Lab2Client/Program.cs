using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class ProgramA
{
    static RSACryptoServiceProvider rsaProviderA = new RSACryptoServiceProvider();
    static AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
    static RSACryptoServiceProvider signatureProviderA = new RSACryptoServiceProvider(1024);

    static TcpClient tcpClient = new TcpClient("127.0.0.1", 1234);
    static NetworkStream clientStream = tcpClient.GetStream();

    static void Main()
    {
        // Участник А - создание ключевой пары подписи и генерация сессионного ключа

        string publicKeyA = ExportPublicKey(signatureProviderA);
        byte[] sessionKey = GenerateSessionKey();
        Console.WriteLine($"A: Session key {BitConverter.ToString(sessionKey)}");

        // Принимаем одно сообщение от сервера
        byte[] receivedBytes = new byte[243];
        clientStream.Read(receivedBytes, 0, receivedBytes.Length);
        string publicKeyB = Encoding.ASCII.GetString(receivedBytes);
        Console.WriteLine($"A: Получили PublicKey-A {publicKeyB}");
        ImportPublicKey(publicKeyB, rsaProviderA);



        // Участник А и Б - обмен сессионным ключом
        byte[] encryptedSessionKey = rsaProviderA.Encrypt(sessionKey, false);
        byte[] signature = signatureProviderA.SignData(encryptedSessionKey, new SHA256CryptoServiceProvider());
        Send(encryptedSessionKey);
        Console.WriteLine($"A: Отправили зашифрованный сессионный ключ {BitConverter.ToString(encryptedSessionKey)}");
        Send(signature);
        Console.WriteLine($"A: Отправили подпись {BitConverter.ToString(signature)}");
        Send(Encoding.ASCII.GetBytes(publicKeyA));
        Console.WriteLine($"A: Отправили PublicKey-A {publicKeyA}");


        string message = "Privet medved";

        byte[] iv = new byte[16];
        Array.Clear(iv, 0, iv.Length);
        byte[] encryptedMessage = EncryptStringToBytes_Aes(message, sessionKey, iv);
        byte[] messageSign = signatureProviderA.SignData(encryptedMessage, new SHA256CryptoServiceProvider());
        Send(encryptedMessage);
        Console.WriteLine($"A: Отправили {message}  enc = {BitConverter.ToString(encryptedMessage)}");
        Send(messageSign);
        Console.WriteLine($"A: Отправили подпись {BitConverter.ToString(messageSign)}");

        Console.ReadLine();
        tcpClient.Close();
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

    static void Send(byte[] data)
    {
        clientStream.Write(data, 0, data.Length);
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
