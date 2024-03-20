using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static RSACryptoServiceProvider rsaProviderA = new RSACryptoServiceProvider();
    static RSACryptoServiceProvider rsaProviderB = new RSACryptoServiceProvider();
    static AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
    static RSACryptoServiceProvider signatureProviderA = new RSACryptoServiceProvider(1024);
    static RSACryptoServiceProvider signatureProviderB = new RSACryptoServiceProvider(1024);
    static IPAddress localIp = new IPAddress(new byte[] { 127, 0, 0, 1 });
    static IPEndPoint ipEndPoint = new(localIp, 1024);
    static Socket listener = new(ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
    static Socket client = new(ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

    static async Task Main(string[] args)
    {
        // Участник Б - создание ключевой пары шифрования
        string publicKeyB = ExportPublicKey(rsaProviderB);

        // Участник А - создание ключевой пары подписи и генерация сессионного ключа
        
        string publicKeyA = ExportPublicKey(signatureProviderA);
        byte[] sessionKey = GenerateSessionKey();
        Console.WriteLine($"A: Session key {BitConverter.ToString(sessionKey)}");

        // Участник А - экспорт ключевой пары подписи
        string signatureKeyA = ExportPublicKey(signatureProviderA);
        //SendDataServer(sessionKey);
        //byte[] recieved = ReceiveDataClient();
        

        // Участник Б - отправка открытого ключа шифрования
        //SendData(publicKeyB, 11000);

        // Участник А - импорт открытого ключа шифрования участника Б
        //byte[] receivedPublicKeyB = ReceiveData(11000);
        ImportPublicKey(publicKeyB, rsaProviderA);

        // Участник А - отправка открытого ключа проверки
        //SendData(publicKeyA, 11001);

        // Участник Б - импорт открытого ключа проверки участника А
        //byte[] receivedPublicKeyA = ReceiveData(11001);
        ImportPublicKey(publicKeyA, signatureProviderB);

        // Участник А и Б - обмен сессионным ключом
        byte[] encryptedSessionKey = rsaProviderA.Encrypt(sessionKey, false);
        byte[] signature = signatureProviderA.SignData(encryptedSessionKey, new SHA256CryptoServiceProvider());
        //SendData(encryptedSessionKey, 11000);

        byte[] decryptSessionKey = rsaProviderB.Decrypt(encryptedSessionKey, false);
        signatureProviderB.FromXmlString(signatureKeyA);
        bool verify = signatureProviderB.VerifyData(encryptedSessionKey, new SHA256CryptoServiceProvider(), signature);
        Console.WriteLine($"B: Session key {BitConverter.ToString(decryptSessionKey)}");
        Console.WriteLine($"Signature {verify}");

        // В данном месте участник А и Б могут использовать сессионный ключ для шифрования данных.

        Console.ReadLine();
    }

    static void SendDataClient(byte[] data)
    {
        client.Send(data);
    }

    static void SendDataServer(byte[] data)
    {
        while (listener.Available == 1)
        {
            if (listener.Connected)
            {
                listener.Send(data);
                return;
            }
        }
        
    }

    static byte[] ReceiveDataClient()
    {
        while (client.Available == 1)
        {
            if (client.Connected)
            {
                var buffer = new byte[1_024];
                var received = client.Receive(buffer, SocketFlags.None);
                return buffer;
                var response = Encoding.UTF8.GetString(buffer, 0, received);
                return Encoding.UTF8.GetBytes(response);
            }
        }
        return new byte[0];

    }

    static byte[] ReceiveDataServer()
    {
        var buffer = new byte[1_024];
        var received = listener.Receive(buffer, SocketFlags.None);
        return buffer;
        var response = Encoding.UTF8.GetString(buffer, 0, received);
        return Encoding.UTF8.GetBytes(response);
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

    // Метод для отправки данных по сокету
    static void SendData(byte[] data, int port)
    {
        using (Socket senderSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
        {
            senderSocket.Connect(IPAddress.Loopback, port);
            senderSocket.Send(data);
            senderSocket.Shutdown(SocketShutdown.Both);
        }
    }

    // Метод для приема данных по сокету
    static byte[] ReceiveData(int port)
    {
        using (Socket receiverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
        {
            receiverSocket.Bind(new IPEndPoint(IPAddress.Loopback, port));
            receiverSocket.Listen(1);

            Socket clientSocket = receiverSocket.Accept();
            byte[] buffer = new byte[1024];
            int bytesRead = clientSocket.Receive(buffer);
            byte[] receivedData = new byte[bytesRead];
            Array.Copy(buffer, receivedData, bytesRead);

            clientSocket.Shutdown(SocketShutdown.Both);
            return receivedData;
        }
    }
}
