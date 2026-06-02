using System;
using System.IO;
using System.Security.Cryptography;

namespace SSForensic.Services
{
    public static class FileHasher
    {
        // Files larger than this are not hashed in full: a replaced cheat binary is
        // never hundreds of MB, and hashing a huge file would stall the whole scan.
        private const long MaxHashBytes = 256L * 1024 * 1024; // 256 MB

        public static string Sha256(string filePath)
        {
            try
            {
                var info = new FileInfo(filePath);
                if (info.Length > MaxHashBytes)
                    return "(skipped: file too large)";

                using var sha = SHA256.Create();
                // Large sequential buffer = far fewer syscalls than the default 4 KB.
                using var stream = new FileStream(
                    filePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete,
                    bufferSize: 1024 * 1024,
                    options: FileOptions.SequentialScan);

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
