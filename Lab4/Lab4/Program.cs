using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public class Program
{
    public static void Main()
    {
        string certName = "cn=foobar";
        // Создание самоподписанного сертификата
        var rsa = RSA.Create(2048); // создание RSA ключа
        var req = new CertificateRequest(certName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        // Добавление расширения X509KeyUsage
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));


        // Установка сертификата в хранилище
        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
        store.Close();
        

        // Подготовка данных для подписи
        byte[] data = Encoding.UTF8.GetBytes("Текст для подписи");

        // Создание подписи
        byte[] signature;
        using (var csp = cert.GetRSAPrivateKey())
        {
            signature = csp.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        Console.WriteLine(Convert.ToBase64String(signature));

        // Проверка подписи
        bool isSignatureValid;
        using (var csp = cert.GetRSAPublicKey())
        {
            isSignatureValid = csp.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        Console.WriteLine($"Подпись действительна: {isSignatureValid}");
        store.Close();
    }
}
