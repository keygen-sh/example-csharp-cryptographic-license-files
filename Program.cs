using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Linq;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using NSec.Cryptography;

public class Program
{
  private const string publicKey = "e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788";

  public class LicenseFile
  {
    public string enc { get; set; }
    public string sig { get; set; }
    public string alg { get; set; }
  }

  public static void Main(string[] args)
  {
    string licenseFilePath = null;
    string licenseKey = null;

    // Parse command line args
    for (var i = 0; i < args.Length; i++)
    {
      var arg = args[i];

      switch (arg)
      {
        case "--path":
          licenseFilePath = args[i + 1];

          break;
        case "--key":
          licenseKey = args[i + 1];

          break;
      }
    }

    if (string.IsNullOrEmpty(licenseFilePath))
    {
      Console.WriteLine("License file path is required: use the --path flag");

      return;
    }

    if (string.IsNullOrEmpty(licenseKey))
    {
      Console.WriteLine("License key is required: use the --key flag");

      return;
    }

    if (!File.Exists(licenseFilePath))
    {
      Console.WriteLine($"Path does not exist or is inaccessible: {licenseFilePath}");

      return;
    }

    // Read and parse signed license file (removing cert header, newlines and footer)
    var licenseFile = File.ReadAllText(licenseFilePath);
    var encodedPayload = Regex.Replace(licenseFile, "(^-----BEGIN LICENSE FILE-----\\n|\\n|-----END LICENSE FILE-----\\n$)", "");
    var payloadBytes = Convert.FromBase64String(encodedPayload);
    var payload = Encoding.UTF8.GetString(payloadBytes);
    var encryptedData = "";
    var encodedSignature = "";
    var algorithm = "";

    // Deserialize license file certificate
    try
    {
      var lic = JsonSerializer.Deserialize<LicenseFile>(payload);

      encryptedData = lic.enc;
      encodedSignature = lic.sig;
      algorithm = lic.alg;
    }
    catch (JsonException e)
    {
      Console.WriteLine($"Failed to parse license file: {e.Message}");

      return;
    }

    // Verify license file algorithm
    if (algorithm != "aes-256-gcm+ed25519")
    {
      Console.WriteLine("Unsupported algorithm!");

      return;
    }

    // Verify signature
    var ed25519 = SignatureAlgorithm.Ed25519;
    var signatureBytes = Convert.FromBase64String(encodedSignature);
    var signingDataBytes = Encoding.UTF8.GetBytes($"license/{encryptedData}");
    var publicKeyBytes = Convert.FromHexString(publicKey);
    var key = PublicKey.Import(ed25519, publicKeyBytes, KeyBlobFormat.RawPublicKey);

    if (ed25519.Verify(key, signingDataBytes, signatureBytes))
    {
      Console.WriteLine("License file is valid! Decrypting...");

      // Decrypt license file dataset
      var plaintext = "";
      try
      {
        var encodedCipherText = encryptedData.Split(".", 3)[0];
        var encodedIv = encryptedData.Split(".", 3)[1];
        var encodedTag = encryptedData.Split(".", 3)[2];
        var cipherText = Convert.FromBase64String(encodedCipherText);
        var iv = Convert.FromBase64String(encodedIv);
        var tag = Convert.FromBase64String(encodedTag);
        var secret = new byte[32];

        // Hash license key to get decryption secret
        try
        {
          var licenseKeyBytes = Encoding.UTF8.GetBytes(licenseKey);
          var sha256 = new Sha256();

          secret = sha256.Hash(licenseKeyBytes);
        }
        catch (Exception e)
        {
          Console.WriteLine($"Failed to hash license key: {e.Message}");

          return;
        }

        // Init AES-GCM
        var cipherParams = new AeadParameters(new KeyParameter(secret), 128, iv);
        var aesEngine = new AesEngine();
        var cipher = new GcmBlockCipher(aesEngine);

        cipher.Init(false, cipherParams);

        // Concat auth tag to ciphertext
        var input = cipherText.Concat(tag).ToArray();
        var output = new byte[cipher.GetOutputSize(input.Length)];

        // Decrypt
        var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        cipher.DoFinal(output, len);

        // Convert decrypted bytes to string
        plaintext = Encoding.UTF8.GetString(output);
      }
      catch (Exception e)
      {
        Console.WriteLine($"Failed to decrypt license file: {e.Message}");

        return;
      }

      Console.WriteLine("License file was successfully decrypted!");
      Console.WriteLine($"Decrypted: {plaintext}");
    }
    else
    {
      Console.WriteLine("Invalid license file!");
    }
  }
}
