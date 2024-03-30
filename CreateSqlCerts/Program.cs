/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Create Root CA Certificate and SQL Server Certificate
// Written by Michael Howard, Azure Data Platform, Microsoft Corp.
// 
// Code to setup a Certificate Authority using .NET
// This is for *experimental purposes only* so you don't need to use self-signed certificates.
// So long as the root CA cert is installed in the Root CA store there is no need to use 
// TrustServerCert=true in SQL connection strings.
// // This mimics a PKI hierarchy without setting up a PKI hierarchy!
//
// Background info:
// https://learn.microsoft.com/en-US/sql/database-engine/configure-windows/configure-sql-server-encryption
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#region Cert Stuff
const int NotBeforeSkew = -2; // 2 Hour skew for the notBefore value

static X509Certificate2 CreateRootCertificate(string caName)
{
    var rsa = RSA.Create(4096);

    var subject = new X500DistinguishedName($"CN={caName}");
    var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

    var notBefore = DateTimeOffset.UtcNow.AddHours(NotBeforeSkew);
    var notAfter = notBefore.AddYears(2);

    return request.CreateSelfSigned(notBefore, notAfter);
}

static X509Certificate2 CreateServerCertificate(string subjectName, X509Certificate2 issuerCertificate)
{
    var rsa = RSA.Create(2048);

    var subject = new X500DistinguishedName($"CN={subjectName}");
    var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                                            new OidCollection { 
                                                new Oid("1.3.6.1.5.5.7.3.1"),   // Client Authentication 
                                                new Oid("1.3.6.1.5.5.7.3.2") }, // Server Authentication
                                            true)); 

    var notBefore = DateTimeOffset.UtcNow.AddHours(NotBeforeSkew);
    var notAfter = notBefore.AddYears(1);

    // Get the CA private key for signing
    using RSA? issuerPrivateKey = issuerCertificate.GetRSAPrivateKey();
    var serverCertificate = request.Create(issuerCertificate.SubjectName, 
            X509SignatureGenerator.CreateForRSA(issuerPrivateKey, RSASignaturePadding.Pkcs1), 
            notBefore, notAfter,
    Guid.NewGuid().ToByteArray());

    // need to get the private key from the RSA object
    return serverCertificate.CopyWithPrivateKey(rsa);
}

#endregion

#region Main
// Create and save the Root CA certificate
var rootCACertFilename = "RootCA.cer";
var rootCertificate = CreateRootCertificate("Mikehow Experimental Root CA");
File.WriteAllBytes(rootCACertFilename, rootCertificate.Export(X509ContentType.Cert));

// Create and save the Server certificate
var hostName = Dns.GetHostName();

Console.Write("Enter PFX password: ");
var pfxPwd = Console.ReadLine();
var serverCertFilename = "ServerCert.pfx";
var serverCertWithPrivateKey = CreateServerCertificate(hostName, rootCertificate);
File.WriteAllBytes(serverCertFilename, serverCertWithPrivateKey.Export(X509ContentType.Pfx, pfxPwd));

Console.WriteLine("Success!");
Console.WriteLine($"Root CA cert is in {rootCACertFilename}");
Console.WriteLine($"Server cert and private key is in {serverCertFilename} encrypted with {pfxPwd}");
#endregion