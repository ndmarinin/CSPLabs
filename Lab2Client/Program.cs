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

        string message = "Hello, world";
        byte[] messageByte = Encoding.ASCII.GetBytes(message);
        byte[] encryptedMessage = rsaProviderA.Encrypt(messageByte, false);
        byte[] signatureMessage = signatureProviderA.SignData(encryptedMessage, new SHA256CryptoServiceProvider());
        Send(encryptedSessionKey);
        Console.WriteLine($"A: Отправили зашифрованный сообщение {BitConverter.ToString(encryptedSessionKey)}");
        Send(signature);
        Console.WriteLine($"A: Отправили подпись сообщение {BitConverter.ToString(signature)}");


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

}
