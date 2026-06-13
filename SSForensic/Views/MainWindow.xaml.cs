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

        private void RecordsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            // Only react to double-clicks on an actual row, not headers/scrollbars.
            if (e.OriginalSource is DependencyObject src && FindParentRow(src) == null)
                return;

            if (sender is DataGrid grid && grid.SelectedItem is ReplaceRecord rec)
            {
                var win = new UsnHistoryWindow(rec) { Owner = this };
                win.Show();
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
