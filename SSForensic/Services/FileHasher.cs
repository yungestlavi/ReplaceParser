using System;
using System.IO;
using System.Security.Cryptography;

namespace SSForensic.Services
{
    public static class FileHasher
    {
        public static string Sha256(string filePath)
        {
            try
            {
                using var sha = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                byte[] hash = sha.ComputeHash(stream);
                return Convert.ToHexString(hash);
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}
