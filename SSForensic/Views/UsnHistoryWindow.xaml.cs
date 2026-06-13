using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using SSForensic.Models;

namespace SSForensic.Views
{
    public partial class UsnHistoryWindow : Window
    {
        public UsnHistoryWindow(ReplaceRecord record)
        {
            InitializeComponent();
            DataContext = new UsnHistoryViewModel(record);
        }

        private void CloseClick(object sender, RoutedEventArgs e) => Close();
    }

    public partial class UsnHistoryViewModel : ObservableObject
    {
        public ObservableCollection<UsnEvent> History { get; } = new();

        [ObservableProperty] private UsnEvent? selectedEvent;

        [ObservableProperty] private string headerUsn = "";
        [ObservableProperty] private string headerName = "";
        [ObservableProperty] private string headerFrn = "";
        [ObservableProperty] private string headerCurrent = "";
        [ObservableProperty] private string headerDirectory = "";
        [ObservableProperty] private string headerReason = "";
        [ObservableProperty] private string headerDate = "";

        private readonly ReplaceRecord _record;

        public UsnHistoryViewModel(ReplaceRecord record)
        {
            _record = record;
            foreach (var ev in record.UsnHistory.OrderBy(e => e.Usn))
                History.Add(ev);

            // Select the first entry so the header is populated immediately.
            SelectedEvent = History.FirstOrDefault();
        }

        partial void OnSelectedEventChanged(UsnEvent? value)
        {
            if (value == null) return;
            HeaderUsn = value.Usn.ToString();
            HeaderName = value.Name;
            HeaderFrn = value.FileReferenceNumber.ToString();
            HeaderDirectory = value.Directory;
            HeaderReason = value.Reason;
            HeaderDate = value.Timestamp.ToString("dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture);

            // "Current file" mirrors JournalTrace: if the latest entry for this file is a
            // delete, the file no longer exists; otherwise report its known path.
            bool deleted = _record.UsnHistory
                .OrderBy(e => e.Usn)
                .LastOrDefault()?.Reason
                .Contains("delete", StringComparison.OrdinalIgnoreCase) ?? false;
            HeaderCurrent = deleted ? "File was deleted"
                          : (string.IsNullOrEmpty(_record.ReplacementPath) ? "(unknown)" : _record.ReplacementPath);
        }
    }
}
