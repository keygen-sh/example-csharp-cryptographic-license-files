using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using NSec.Cryptography;

public class Program
{
  private const string licenseFile = "-----BEGIN LICENSE FILE-----\neyJlbmMiOiJsWjIySUlNL3FqRC9WdVByeUVzVFU3UjV3U1JZTW1aeE05WlBW\nV2d5cDYyT0hOUWplbXJXRkthVUJaUjc0elplWmFJbUoyc29lTGk4S2NqZVhK\nNjJPeUNvRFJRMk5WZUhvK0hxY0RSNEtkRUN2MlFiR3JVZ0VvdkJFelZCbWdX\nYlh5eTNnUUxNOTQ3MXBOUXRVNE9MVFhONmFka2gzdXdNeklRUS93b2U1SENq\naW5xVGFmSnJxcjhyQkc2emxORCtSb0VvT04wTlJlWTJyd0hZMGxPQkdNZlZU\nOWJ0WFAzNFFTTTBQbFhVNVNIZDhOVUp0MlZaVEh6QmlpakMrRnNaQ2dpSzcw\nWXNKN2wvV3pHNXVxUE1zYnZGYVgwSG4rczljRjZ2OHp0VVR5UWIrVGM4ZWdL\nTitJQXIydTZTNnVnM2RxaVVyZDNJUEZNU01ZQ0ZOZ2pSOXp0bmcrK0RXZDh4\nV2FCVmh0UDV1Tk9laEdZU0FrRlNyVk1xdjBnVkRuZXV2VHlleCtscisyVWds\nS0YwWkZ4WVNRTFlHWmtNMjVnV21WREVpeGNBNEJPektLM05NSlNLRjd5SW9T\nZmpvUTJYODJJT1NBQlRmSThHdk5teGZIUW1pVTA4aWFpMS9SWDNFcUJVWUpU\nK2N5Qkp5NG54RklHV1hFdFhjRnYyQVdEUm9yZmZYUGlBNk1DcThWZjlVMm5v\nY1NwWU9tQWM1UEh4Tlc5TjdmcEZvNFFOZEJXaVlac0VKZXk0bVY5UksvWjB0\najIzZnk1SVFweGc5NUpDbXUyWGxhNEk3NnlYNHQxTTFuaHRDOFo3UlJrNlBO\nR2dpd1pMM2NrYnhpRVREQ2NVYUg3d0xpelQ1TkdGa0hWNjY2TC8yTTM5SWFj\nZTVud09oYUdBcVJNQVNKMU9LK2M5OUZUREtzN09zUVpwTko0ZHcwcEZ0a3hG\nUGNWcVBIT015a1VtTW5tL0dyc0lYbmUxU1VJb29XVCtPSTlWamNNRVlHUWhC\nNHBJZ3czVzMwMHNNczhReDV2blVOMlNtb3VBaG1CcmU0eTdkdFgzRUFyMm03\nSWZMU0lnMkhxVU5jRVpSUklucGF1ckZ5YW5BdnRIemR1L08rNEk1YWN0cWdN\na3FqYjI5MU4rbkNaaHpNNHpkVkVEVkFEbm1yZnUyZzJqTlJNdWx6a044RmhR\ndTlJZTdWaFBHL2RaTTF0N2MrOTFac3lzUHZKc1RrcGRmUjdpbzROb3hQVm16\nT2YwRGtveFl2NlJNZWdCRGRsZUhDTDV2aDhRcWo1MkVpTnVXNXM0cnc4MXRF\nT0FOSWIvS25YdUtueUVLeUdCYWdpbTJKMVBra1ltajgzbVNLb29KMFlleXdY\nWG8yNGFuRDFqa0ZOL0RISVRkNWlWMmxmY1JYMDBwSHZ0NW5HMDdVcXJzZnZQ\nV2VFNVpWUENXZ01jSGxWM01ncGlMWHpnUi9VVXVSWnNZYm5CMHlJTDhHUHdH\nUWgzKyt4OGJhOS9MNGRGTGN3elcyV0JlTmU1T09rcTcvWXI1SXdGTWZ0dDd5\nTm1pTjR3ZnhTbXZ4cGcxNjBnVDZJeVFoYWIvTFZTTS96eXhhNUVKb0tIL0R4\nbTBELzNYNmFnZ21tUGgza3hCZUYweWNxbnkyMVhiZi8xQXBTbURHQ1JtaVE1\nVWJFSVJ5SUlIbXJoa1NEZmozdzFmd1BIV0dIWFQ4UUF2bjQ5WUNhTFpPYXZo\nWWo0bEZ0K2dQdXVaMUV1L1NTZEFoVisxMFU4MHFka3JqOC9HYmtaZlJRU3I0\ncTlncEc0TXIxOTh5K1R5elBzYUg3YnRadmprK3pkbXdSUEQ5UGtWNVpEVkM1\nT3hNYTN5R3Fla1FlVzN1VUY5VUpoejcrd1VGbnRjMGV4NHRCTDQ2N2J3bHg1\nWmpiR2YvOW5XeUZuMXR4Y2h5TjJISEs2allhb25JSG9kRXFGTE14RUNWMGFh\ndnBPT0RZbndLaXBrU2dQcnFIK0kxV1NuaVp5L3FTNU5rdnlJK012YmtiNU1a\nbW9iN09VdWFyVi92Y21oM1gwT3Zub0FhbUtQaC9vT2kycDNMOTVQUXZUbXBR\nVGFLaFZ5b3dNa1QwOExDZ29GcUVZWmNJMlhDdmFtdEovdnNkSWhqZWxINkow\nMWhzQkczVFlPRVl4M0piRzFsM0gvSUZyUGcxcmdNa3BwK2txR2RXL2p4blFN\ncDlFVkFvL28xMzNTZTdNTE91anBsYlRjV05EMnhUdHY1elEraXpJUmpsNXhB\ndmpkK2dYYWg1UFNlazZUMER3Ynl4R0J4ek5iRWpadm5wSTJsK0JaUTlKOFFk\nWU5TSjdFZzJ0TzhTWUh3MjZ2ZWhQY2poeEg3alhOMHM2aHdVMjAzNkk0TnRG\nODZoQUNCQ2NoMStubUczZnd6UnJaeVNmTFRocWFFc2lyaTdWdWJEQjg5NFJs\nV01jb2JkaGxjRHpCVUxubTFCNk5HOTJtZ2xUSUl4cE9WM2JNcUFJRGxXNkFE\nK2FQVjAvNklJdzBjanpSclBpMnkrMFlQSEwxenVqbmVjZ1V5ejVCdnpXNDUx\ndTUrdmx0Si91VFU2TFVjUWM1M1g3S3B3TDFSTUxKQ0t4Mm5CcW5IaWZ5RytF\nV29OaG5Ib2JXN0VPNldVT2QwZFhUUklUcno0M1ZYNUJoNnU1eTFxZ1NZMC9v\nTmJ1VE90Q0JYUkJqa2NTekJGVEh3YW0rNmVNMVljelNjTGpSU0p4Yk9HTDdj\nbzhkS1J4WklRT0JKL1BVSU9pU1Q3cVNIK1Q2RFVDVUY3aWx5NTBrUVdvZlpM\nQUJTNU5iSXRWenNjSGo0Q2UxNjA5VUNVbHNTd3hpSWlWazJ6Y3F6cVI0NEIx\nc1JQNXgvMThhbEFJZFpCdTA4enpsa3lsRUNpa1F2Sml4RHMxMlNyNmg1eGhY\nMGxVNEl5R0ZWVTZZTElRR1R2ZmI2WnNMYW1LZElJdjZlbVRWK3ZoR3czRG0w\nV3F5aHRmY3BMcEJCVCs1L01JR0xtTmFHQ3k3MUpnbDBmVXRCTDFZREdGcjFV\nemRvYTRNV3NxNEtGRnVueC9DRmRpcCsrMUdZSUVCUUJ2ZUVuUUdIb0xESytC\nVnJubkF1V3Z0S2E1ZVAwbEgyMHB5NTJoWGoyR2JLM2xac0lURzRveUhwRmJB\nbUJCdmFtOHNwckpGU2ZtZk8yNmRIci8zemlodndCR1VyNytOSVhHK01EdHpr\nS3ZUMUl0NldVcUJDc2YvTWloYU1zZHhrRjMrYVBITERVK05MNzBnT3BocUZF\nZnpIdGZ4ZVFiTCt2Qml3aG1uTlkraURYWnE0Qm5uYTFIaDMyeDlMcGc5WDg0\nbS9tRVNzZ01lS1R5TXYvMGFodm4zbkRURVJVRG91Rk9FSkU1b3BWS1puOGVp\nSXJ0czVUcEk0RHBKdHpVaFpNUXh4dWRNbHY0SldnMm9MVHFWUWtaQm1xTGlX\nT3RCTnpPTjkwMmFwWWxUbUVOWlQxKzVZRjJMcG1hODJZMm16ZUpNZHZrMitv\nTEJvbUN0Wmt1MGFMMUlDMHlGZjB6QythcjV2VzF5cEpOMWxmR3VleU5iS2No\nbDhGWGMrbFNjdkhGb0poZUlUcWdKOWtneFE3SXpVaC9JMHY0YU1Od25SZTJ6\nR0dEZU8xeTR6NXg3WVBKSU12TFpybldBY3puVThZSm1yUm0rTll6T0tvaGlN\nZzZJdkR3SmhWQkZVcHoyS1VxYkhyaEp1TUJvUHRpSmxkaktOMDVNRjgvZVRP\nRmNoSm4yRU1NWE4zeVY1RWIxTDgxRDlxUFRoNzY0eEluRUdlNnRQdWh0dFJu\nTWFrNythMFFzK3M3TnFtUW4yZFQxQmttM2lTb2szeWFQOWl2SnQxR0NwMy9r\nQVl2b0E9PS41YmpjYytJZ3JxZEF2WkRYLk5xVHhDL1g0VllaSS92MWp2dG5Q\nZlE9PSIsInNpZyI6IjRnRGdUQUNZcC9uN3BuekQyU0N5RUVLd1R0aEpmVmI5\nd2E1dnBkTUZKY2tPZUsrTTNNeWNpNEhrUlJEdW9VUzVUVnMzMC9FYXhmd09o\nd0ZjRUhJOUF3PT0iLCJhbGciOiJhZXMtMjU2LWdjbStlZDI1NTE5In0=\n-----END LICENSE FILE-----\n";
  private const string licenseKey = "key/eyJ0ZXN0IjoxfQ==._f34UAAtNKM8TXGLlnblBGCLSy22Oa_gjp4jn0CpvEuwQ2gAcH0IntFKwtbyV5iWnH9_x8l0R144oHp2_GviAw==";
  private const string publicKey = "e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788";

  public class LicenseFile
  {
    public string enc { get; set; }
    public string sig { get; set; }
    public string alg { get; set; }
  }

  public static void Main()
  {
    // Parse signed license file (removing cert header, newlines and footer)
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
