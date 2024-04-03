/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Create Root CA Certificate and SQL Server Certificate, signed with the CA certificate
// Written by Michael Howard, Azure Data Platform, Microsoft Corp.
// 
// Code to setup a Certificate Authority using .NET
// This is for *experimental purposes only* so you don't need to use self-signed certificates.
// So long as the root CA cert is installed in the Root CA store there is no need to use 
// TrustServerCert=true in SQL connection strings.
// This mimics a PKI hierarchy without setting up a PKI hierarchy!
//
// NOTE: This code lacks error handling, this is to make the code a little clearer.
//
// Background info:
// https://learn.microsoft.com/en-US/sql/database-engine/configure-windows/configure-sql-server-encryption
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

#region Important Global Names
var hostName = Dns.GetHostName();   // used as the CN for the server certificate
var rootCertificateName = $"{hostName} Experimental Root CA"; // used as the CN for the root CA certificate
var serverCertFriendlyName = $"SQL Server TLS cert for {hostName}";
#endregion

#region Cert Generation 
const int NotBeforeSkew = -2; // 2 Hour skew for the notBefore value

static X509Certificate2 CreateRootCertificate(string caName)
{
    using var rsa = RSA.Create(4096);

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
    using var rsa = RSA.Create(2048);

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

#region Add Certs to Cert Respective Store

void AddRootCaCertToCertStore(string certPath)
{
    using var certificate = new X509Certificate2(certPath);
    var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);
    store.Add(certificate);
    store.Close();
}
void AddServerCertToMachineCertStore(string certPath, string pfxPwd)
{
    using var cert = new X509Certificate2(certPath, pfxPwd, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
    cert.FriendlyName = serverCertFriendlyName;

    var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadWrite);

    store.Add(cert);
    store.Close();
}

#endregion

#region Remove old certs
static void RemovePreviousRootCertificate(string certificateName)
{
    int count = 0;
    using (var rootStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
    {

        rootStore.Open(OpenFlags.ReadWrite);
        foreach (var cert in rootStore.Certificates)
        {
            if (cert.Subject.Contains($"CN={certificateName}"))
            {
                var hash = cert.Thumbprint;
                rootStore.Remove(cert);
                Console.WriteLine($"Removed root cert: '{certificateName}', thumbprint: {hash}");
                count++;
            }
        }
        rootStore.Close();
    }
    if (count == 0) { Console.WriteLine($"No Root CA certificates named '{certificateName}' to remove."); }
}

static void RemovePreviousSignedCertificates(string issuerName)
{
    int count = 0;
    using (var myStore = new X509Store(StoreName.My, StoreLocation.LocalMachine))
    {
        myStore.Open(OpenFlags.ReadWrite);
        foreach (var cert in myStore.Certificates)
        {
            if (cert.Issuer.Contains($"CN={issuerName}"))
            {
                var hash = cert.Thumbprint;
                myStore.Remove(cert);
                Console.WriteLine($"Removed cert signed by: '{issuerName}', thumbprint: {hash}");
                count++;
            }
        }
        myStore.Close();
    }

    if (count==0) { Console.WriteLine($"No certificates issued by '{issuerName}' to remove."); }
}

#endregion

#region Main

Console.Clear();
Console.WriteLine("Create Root CA and SQL Server server Certificates.\nWatch out for important CertStore dialog prompts.");

WindowsPrincipal principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
{
    Console.WriteLine("You must run this program as an administrator.");
    return;
}

Console.WriteLine("Do you want to remove old root and server certificates created by this tool? (y/n)");
var response = Console.ReadKey(true).KeyChar.ToString().ToLower();
if (response[0] == 'y')
{
    RemovePreviousRootCertificate(rootCertificateName);
    RemovePreviousSignedCertificates(rootCertificateName);
}

// Create and save the Root CA certificate
var rootCACertFilename = "RootCA.cer";
var rootCertificate = CreateRootCertificate(rootCertificateName);
File.WriteAllBytes(rootCACertFilename, rootCertificate.Export(X509ContentType.Cert));

// Create and save the Server certificate
Console.Write("Enter PFX password for server cert: ");
var pfxPwd = Console.ReadLine();
var serverCertFilename = "ServerCert.pfx";
var serverCertWithPrivateKey = CreateServerCertificate(hostName, rootCertificate);
File.WriteAllBytes(serverCertFilename, serverCertWithPrivateKey.Export(X509ContentType.Pfx, pfxPwd));

// Add certs to cert store
AddRootCaCertToCertStore(rootCACertFilename);
AddServerCertToMachineCertStore(serverCertFilename, pfxPwd);

Console.WriteLine("\n**Success!**");
Console.WriteLine($"Root CA cert is in {rootCACertFilename} and User->TrustedRoot Cert Store");
Console.WriteLine($"Server cert and private key is in {serverCertFilename} encrypted with {pfxPwd}, and in the Machine->My Cert Store");
#endregion

#region Next Steps
Console.WriteLine("\nPress any key for Next Steps");
Console.ReadKey();

Console.WriteLine("\n\n**NEXT STEPS**");
Console.WriteLine("1. SET KEY ACL");
Console.WriteLine(" - You need to set the ACL on the server's private key so SQL Server can read the key.");
Console.WriteLine(" - Open certlm.msc which is the Local Machine cert store tool.");
Console.WriteLine($" - Expand Personal, Certificates and right click the cert in question, issued to '{hostName}'");
Console.WriteLine(" - Select All Tasks and then click Manage Private Keys.");
Console.WriteLine(" - Click Add to add the SQL Server service account (probably 'NT Service\\MSSQLServer' and give it Read permission.");
Console.WriteLine(" - You can check the service account name is correct by clicking Check Names.");

Console.WriteLine("\n2. CONFIGURE SQL SERVER");
Console.WriteLine(" - You need to configure SQL Server to use the certificate and private key.");
Console.WriteLine(" - Open SQL Server Configuration Manager.");
Console.WriteLine(" - Expand SQL Server Network Configuration, select Protocols for MSSQLSERVER, right click and select Properties.");
Console.WriteLine($" - Go to the Certificate tab and select the certificate you just installed '{serverCertFriendlyName}' from the drop list.");
Console.WriteLine(" - Click OK to save the changes.");

Console.WriteLine("\n3. RESTART SQL SERVER"); 
Console.WriteLine(" - You need to restart SQL Server for the changes to take effect.");
#endregion
