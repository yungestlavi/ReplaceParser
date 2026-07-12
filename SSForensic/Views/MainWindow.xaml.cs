using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Controls;
using SSForensic.Models;

namespace SSForensic.Views
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
            {
                WindowState = WindowState == WindowState.Maximized
                    ? WindowState.Normal
                    : WindowState.Maximized;
            }
            else
            {
                DragMove();
            }
        }

        private void MinimizeBtn_Click(object sender, RoutedEventArgs e)
            => WindowState = WindowState.Minimized;

        private void MaximizeBtn_Click(object sender, RoutedEventArgs e)
            => WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;

        private void CloseBtn_Click(object sender, RoutedEventArgs e)
            => Close();

        private void RecordsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (e.OriginalSource is DependencyObject src && FindParentRow(src) == null)
                return;

            if (sender is DataGrid grid && grid.SelectedItem is ReplaceRecord rec)
            {
                var win = new UsnHistoryWindow(rec) { Owner = this };
                win.Show();
            }
        }

        private void CopyOriginalPath_Click(object sender, RoutedEventArgs e)
        {
            if (GetSelectedRecord() is { } rec && !string.IsNullOrEmpty(rec.OriginalPath))
                Clipboard.SetText(rec.OriginalPath);
        }

        private void CopyReplacementPath_Click(object sender, RoutedEventArgs e)
        {
            if (GetSelectedRecord() is { } rec && !string.IsNullOrEmpty(rec.ReplacementPath))
                Clipboard.SetText(rec.ReplacementPath);
        }

        private void CopyFileName_Click(object sender, RoutedEventArgs e)
        {
            if (GetSelectedRecord() is { } rec && !string.IsNullOrEmpty(rec.ReplacementFileName))
                Clipboard.SetText(rec.ReplacementFileName);
        }

        private void CopyRowTsv_Click(object sender, RoutedEventArgs e)
        {
            if (GetSelectedRecord() is { } rec)
            {
                string ts = rec.ReplaceTimestamp.HasValue
                    ? rec.ReplaceTimestamp.Value.ToString("yyyy-MM-dd HH:mm:ss")
                    : "";
                Clipboard.SetText(
                    $"{ts}\t{rec.ReplacementFileName}\t{rec.OriginalPath}\t{rec.ReplacementPath}\t{rec.ReplaceTypeLabel}");
            }
        }

        private static DataGridRow FindParentRow(DependencyObject d)
        {
            while (d != null && d is not DataGridRow)
                d = VisualTreeHelper.GetParent(d);
            return d as DataGridRow;
        }
    }
}
