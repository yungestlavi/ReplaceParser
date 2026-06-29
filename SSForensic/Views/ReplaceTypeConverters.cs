using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using SSForensic.Models;

namespace SSForensic.Views
{
    /// <summary>
    /// Maps a ReplaceType enum value to a foreground brush for the Type column.
    ///   Explorer → cyan  (#56B6C2)
    ///   Copy     → yellow (#E5C07B)
    ///   Type     → green  (#98C379)
    ///   Hex      → red    (#E06C75)
    ///   Unknown  → muted  (#6B7280)
    /// </summary>
    public sealed class ReplaceTypeToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is ReplaceType rt)
            {
                return rt switch
                {
                    ReplaceType.Explorer => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#56B6C2")),
                    ReplaceType.Copy     => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E5C07B")),
                    ReplaceType.Type     => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#98C379")),
                    ReplaceType.Hex      => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E06C75")),
                    _                    => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6B7280"))
                };
            }
            return Brushes.Gray;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    /// <summary>
    /// Maps a ReplaceType enum value to a human-readable description shown in the tooltip.
    /// </summary>
    public sealed class ReplaceTypeToDescriptionConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is ReplaceType rt)
            {
                return rt switch
                {
                    ReplaceType.Explorer =>
                        "Windows Explorer rename-over replace.\n" +
                        "Pattern: File Delete+Close → Rename Old Name → Rename New Name → Rename New Name+Close.\n" +
                        "The target file was deleted then the source was renamed into its slot.",

                    ReplaceType.Copy =>
                        "Copy-paste overwrite (Ctrl+C / Ctrl+V or drag-drop).\n" +
                        "Pattern: Data Truncation (±Security Change) → Data Extend+Truncation → Data Overwrite+Extend+Truncation (±BasicInfo ±Close).\n" +
                        "Typical of dragging a file onto an existing one in Explorer or using robocopy/xcopy.",

                    ReplaceType.Type =>
                        "Typed or echo-redirect overwrite (e.g. 'type file > target', echo redirect, or small in-place editor).\n" +
                        "Pattern: Data Truncation → Data Extend+Truncation (±Close).\n" +
                        "No Data Overwrite means the file was truncated first, then re-written sequentially.",

                    ReplaceType.Hex =>
                        "Raw / hex-editor write (direct Data Overwrite without the standard Extend+Truncation sequence).\n" +
                        "Typical of hex editors, low-level file patchers, or tools that open a file with GENERIC_WRITE and write in-place.",

                    _ =>
                        "Replace type could not be determined from the USN reason sequence.\n" +
                        "The event pattern did not match Explorer, Copy, Type, or Hex signatures."
                };
            }
            return "Unknown";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
