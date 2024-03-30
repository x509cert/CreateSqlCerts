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
using System.Security.AccessControl;
using System.Security.Principal;

#region Cert Generation 
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

#region Add Certs to Cert Store

static void AddRootCaCertToCertStore(string certPath)
{
    var certificate = new X509Certificate2(certPath);
    var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);
    store.Add(certificate);
    store.Close();
}
static void AddServerCertToMachineCertStore(string certPath, string pfxPwd)
{
    var cert = new X509Certificate2(certPath, pfxPwd, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
    var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadWrite);
    store.Add(cert);
    store.Close();
}

#endregion

#region Set ACL on Server Cert Private Key
// Grant SQL Server service account access to the certificate files
/*
 * static void SetPrivateKeyPermissions(string thumbprint, string userName)
{
    // Open the certificate store and find the certificate
    var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);
    X509Certificate2? certificate = null;
    foreach (var cert in store.Certificates)
    {
        if (cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            certificate = cert;
            break;
        }
    }

    if (certificate == null)
    {
        Console.WriteLine("Certificate not found.");
        return;
    }

    if (!certificate.HasPrivateKey)
    {
        Console.WriteLine("Certificate does not have a private key.");
        return;
    }

    // Get the private key file path
    //var keyPath = certificate.PrivateKey.
    //string fullKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft\\Crypto\\RSA\\MachineKeys", keyPath);

    //var fi = new FileInfo(fullKeyPath);
    //var ac = fi.GetAccessControl();
    //ac.AddAccessRule(new FileSystemAccessRule(@"NT Service\MSSQLServer", FileSystemRights.Read, AccessControlType.Allow));
    //fi.SetAccessControl(ac);

    //Console.WriteLine($"Permissions updated for {userName} on private key: {fullKeyPath}");
}
*/
#endregion

#region Main

WindowsPrincipal principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
{
    Console.WriteLine("You must run this program as an administrator.");
    return;
}

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

// Add certs to cert store
AddRootCaCertToCertStore(rootCACertFilename);
AddServerCertToMachineCertStore(serverCertFilename, pfxPwd);

// Set ACL on the private key
//var thumbPrint = serverCertWithPrivateKey.Thumbprint;
//SetPrivateKeyPermissions(thumbPrint, "NT Service\\MSSQLServer");

Console.WriteLine("Success!");
Console.WriteLine($"Root CA cert is in {rootCACertFilename}");
Console.WriteLine($"Server cert and private key is in {serverCertFilename} encrypted with {pfxPwd}");
#endregion
