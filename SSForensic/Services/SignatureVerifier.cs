using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SSForensic.Services
{
    /// <summary>
    /// Result of an in-depth digital-signature verification of a file.
    /// </summary>
    public class SignatureInfo
    {
        public bool IsSigned { get; set; }
        public bool IsAuthenticodeValid { get; set; }   // WinVerifyTrust says the Authenticode signature is valid
        public bool IsChainTrusted { get; set; }        // X509 chain builds to a trusted root
        public bool IsTimeValid { get; set; }           // now is within NotBefore..NotAfter
        public bool IsSelfSigned { get; set; }
        public bool HasTimestamp { get; set; }

        public string SignerName { get; set; } = string.Empty;
        public string SignerSubject { get; set; } = string.Empty;
        public string IssuerName { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public string HashAlgorithm { get; set; } = string.Empty;

        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }
        public int ChainLength { get; set; }

        public string AuthenticodeStatus { get; set; } = string.Empty;
        public List<string> ChainErrors { get; set; } = new();

        /// <summary>
        /// Short verdict used for colour-coding / one-line display.
        /// </summary>
        public string Verdict
        {
            get
            {
                if (!IsSigned) return "UNSIGNED";
                if (IsAuthenticodeValid && IsChainTrusted && IsTimeValid) return "VALID";
                if (!IsTimeValid) return "EXPIRED";
                if (IsSelfSigned) return "SELF-SIGNED";
                if (!IsChainTrusted) return "UNTRUSTED";
                return "INVALID";
            }
        }

        public string Summary()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Verdict:        {Verdict}");
            sb.AppendLine($"Signed:         {(IsSigned ? "yes" : "no")}");
            if (IsSigned)
            {
                sb.AppendLine($"Authenticode:   {(IsAuthenticodeValid ? "valid" : "INVALID")}  ({AuthenticodeStatus})");
                sb.AppendLine($"Chain trusted:  {(IsChainTrusted ? "yes" : "NO")}");
                sb.AppendLine($"Time valid:     {(IsTimeValid ? "yes" : "NO (expired / not yet valid)")}");
                sb.AppendLine($"Self-signed:    {(IsSelfSigned ? "YES" : "no")}");
                sb.AppendLine($"Timestamped:    {(HasTimestamp ? "yes" : "no")}");
                if (!string.IsNullOrEmpty(SignerName))    sb.AppendLine($"Signer:         {SignerName}");
                if (!string.IsNullOrEmpty(SignerSubject))  sb.AppendLine($"Subject:        {SignerSubject}");
                if (!string.IsNullOrEmpty(IssuerName))     sb.AppendLine($"Issuer:         {IssuerName}");
                if (!string.IsNullOrEmpty(SerialNumber))   sb.AppendLine($"Serial:         {SerialNumber}");
                if (!string.IsNullOrEmpty(Thumbprint))     sb.AppendLine($"Thumbprint:     {Thumbprint}");
                if (!string.IsNullOrEmpty(HashAlgorithm))  sb.AppendLine($"Hash alg:       {HashAlgorithm}");
                if (NotBefore.HasValue)                    sb.AppendLine($"Not before:     {NotBefore:yyyy-MM-dd HH:mm:ss}");
                if (NotAfter.HasValue)                     sb.AppendLine($"Not after:      {NotAfter:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"Chain length:   {ChainLength}");
                foreach (var e in ChainErrors)
                    sb.AppendLine($"  chain: {e}");
            }
            return sb.ToString().TrimEnd();
        }
    }

    /// <summary>
    /// Verifies a file's Authenticode signature in depth: extracts the embedded
    /// certificate, builds and validates the X509 chain, and calls the native
    /// WinVerifyTrust API for the authoritative trust decision (this also covers
    /// catalog-signed Windows files that have no embedded certificate).
    /// </summary>
    public static class SignatureVerifier
    {
        public static SignatureInfo Verify(string filePath)
        {
            var info = new SignatureInfo();

            if (string.IsNullOrWhiteSpace(filePath) || !System.IO.File.Exists(filePath))
                return info;

            // --- 1) Authoritative trust decision from the OS (WinVerifyTrust) ---
            int trustResult = int.MinValue;
            try
            {
                trustResult = WinVerifyTrustFile(filePath);
                info.AuthenticodeStatus = DescribeTrustResult(trustResult);
                info.IsAuthenticodeValid = trustResult == 0;
            }
            catch (Exception ex)
            {
                info.AuthenticodeStatus = "WinVerifyTrust failed: " + ex.Message;
            }

            // --- 2) Try to pull the embedded Authenticode certificate ---
            X509Certificate2? cert = null;
            try
            {
                var raw = X509Certificate.CreateFromSignedFile(filePath);
                cert = new X509Certificate2(raw);
            }
            catch
            {
                cert = null;
            }

            if (cert != null)
            {
                info.IsSigned = true;
                info.SignerSubject = cert.Subject;
                info.SignerName    = ExtractCn(cert.Subject);
                info.IssuerName    = ExtractCn(cert.Issuer);
                info.SerialNumber  = cert.SerialNumber ?? string.Empty;
                info.Thumbprint    = cert.Thumbprint ?? string.Empty;
                info.HashAlgorithm = cert.SignatureAlgorithm?.FriendlyName ?? string.Empty;
                info.NotBefore     = cert.NotBefore;
                info.NotAfter      = cert.NotAfter;

                var now = DateTime.Now;
                info.IsTimeValid = now >= cert.NotBefore && now <= cert.NotAfter;
                info.IsSelfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase);

                // --- 3) Build and validate the X509 chain ---
                try
                {
                    using var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                    bool built = chain.Build(cert);
                    info.IsChainTrusted = built;
                    info.ChainLength = chain.ChainElements.Count;

                    foreach (X509ChainStatus st in chain.ChainStatus)
                    {
                        if (st.Status != X509ChainStatusFlags.NoError)
                            info.ChainErrors.Add($"{st.Status}: {st.StatusInformation?.Trim()}");
                    }
                }
                catch (Exception ex)
                {
                    info.ChainErrors.Add("chain build error: " + ex.Message);
                }
            }
            else
            {
                // No embedded cert. If WinVerifyTrust still says the file is valid,
                // it is a catalog-signed OS file (driver / inbox binary).
                if (info.IsAuthenticodeValid)
                {
                    info.IsSigned = true;
                    info.IsChainTrusted = true;
                    info.IsTimeValid = true;
                    info.SignerName = "(catalog-signed)";
                }
            }

            return info;
        }

        private static string ExtractCn(string distinguishedName)
        {
            if (string.IsNullOrEmpty(distinguishedName)) return string.Empty;
            foreach (var part in distinguishedName.Split(','))
            {
                var p = part.Trim();
                if (p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return p.Substring(3).Trim();
            }
            return distinguishedName;
        }

        // ---------------------------------------------------------------
        //  WinVerifyTrust P/Invoke
        // ---------------------------------------------------------------
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;
        private const uint WTD_SAFER_FLAG = 0x100;

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            [MarshalAs(UnmanagedType.LPWStr)] public string pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

        private static int WinVerifyTrustFile(string filePath)
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            IntPtr pData = IntPtr.Zero;
            try
            {
                Marshal.StructureToPtr(fileInfo, pFile, false);

                var data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pFile = pFile,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = null!,
                    dwProvFlags = WTD_SAFER_FLAG,
                    dwUIContext = 0
                };

                pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
                Marshal.StructureToPtr(data, pData, false);

                Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int result = WinVerifyTrust(IntPtr.Zero, action, pData);

                // Close the verification state.
                data = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(data, pData, false);
                WinVerifyTrust(IntPtr.Zero, action, pData);

                return result;
            }
            finally
            {
                if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
                Marshal.FreeHGlobal(pFile);
            }
        }

        private static string DescribeTrustResult(int result)
        {
            uint r = unchecked((uint)result);
            return r switch
            {
                0x00000000 => "Valid",
                0x800B0100 => "No signature present",
                0x800B0101 => "Certificate expired",
                0x800B0109 => "Untrusted root",
                0x800B010A => "No trusted signer chain",
                0x800B010C => "Certificate revoked",
                0x800B0111 => "Certificate explicitly distrusted",
                0x800B0004 => "Subject not trusted for action",
                0x80096010 => "Invalid digest (file tampered)",
                0x80092026 => "Security policy / catalog error",
                0x800B0003 => "Unknown trust provider",
                _ => $"0x{r:X8}"
            };
        }
    }
}
