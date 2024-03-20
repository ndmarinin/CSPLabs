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

        // Message
        byte[] receivedMessage = new byte[243];
        stream.Read(receivedMessage, 0, receivedMessage.Length);

        byte[] receivedSignature = new byte[243];
        stream.Read(receivedSignature, 0, receivedSignature.Length);


        byte[] decryptMessage = rsaProviderB.Decrypt(receivedMessage, false);
        Console.WriteLine(Encoding.ASCII.GetString(decryptMessage));
        bool verifyMessage = signatureProviderB.VerifyData(encryptedSessionKey, new SHA256CryptoServiceProvider(), signature);
        Console.WriteLine($"B: Signature message {verifyMessage}");


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

}
