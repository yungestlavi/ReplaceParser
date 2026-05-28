using System;
using System.Collections.Generic;
using SysEvt = System.Diagnostics.Eventing.Reader;
using SSForensic.Models;

namespace SSForensic.Forensics
{
    /// <summary>
    /// Legacy event-log reader. The current analyzer (v1.1+) uses ONLY the USN journal
    /// and fsutil for replace detection, so this class is no longer wired in by default.
    /// Kept for future extensions / optional event log enrichment.
    /// </summary>
    public class ForensicEventLogReader
    {
        public IEnumerable<ForensicEvidence> ReadChannel(string channel, EvidenceSource source, DateTime? since = null)
        {
            SysEvt.EventLogQuery query;
            try
            {
                string xpath = "*";
                if (since.HasValue)
                {
                    var iso = since.Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z");
                    xpath = $"*[System[TimeCreated[@SystemTime>='{iso}']]]";
                }
                query = new SysEvt.EventLogQuery(channel, SysEvt.PathType.LogName, xpath) { ReverseDirection = true };
            }
            catch { yield break; }

            SysEvt.EventLogReader? reader = null;
            try { reader = new SysEvt.EventLogReader(query); }
            catch { yield break; }

            using (reader)
            {
                SysEvt.EventRecord? rec;
                while (true)
                {
                    try { rec = reader.ReadEvent(); }
                    catch { yield break; }
                    if (rec == null) yield break;

                    string desc;
                    try { desc = rec.FormatDescription() ?? string.Empty; }
                    catch { desc = $"EventID={rec.Id}"; }

                    yield return new ForensicEvidence
                    {
                        Source = source,
                        Timestamp = rec.TimeCreated ?? DateTime.MinValue,
                        Description = $"[{channel}] EventID {rec.Id}: {Truncate(desc, 500)}",
                        RawData = desc
                    };

                    rec.Dispose();
                }
            }
        }

        private static string Truncate(string s, int max) =>
            s.Length <= max ? s : s.Substring(0, max) + "...";
    }
}
