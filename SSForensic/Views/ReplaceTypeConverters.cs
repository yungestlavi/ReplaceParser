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
                        "Sostituzione tramite Windows Explorer (drag-and-drop o copia con stesso nome).\n" +
                        "Pattern: File delete+Close → Rename: old name → Rename: new name → Rename: new name+Close.\n" +
                        "Il file di destinazione viene eliminato e il nuovo file rinominato al suo posto.",

                    ReplaceType.Copy =>
                        "Sostituzione tramite copia (Ctrl+C/Ctrl+V, drag-drop, robocopy/xcopy).\n" +
                        "Pattern: Data truncation (±Security change) → Data extend+truncation → Data overwrite+extend+truncation (±Basic info change ±Close).\n" +
                        "Tipico di un file copiato sopra uno esistente.",

                    ReplaceType.Type =>
                        "Sostituzione tramite scrittura sequenziale (comando 'type', redirect echo, piccolo editor).\n" +
                        "Pattern: Data truncation → Data extend+truncation (±Close).\n" +
                        "Nessun 'Data overwrite': il file viene troncato e poi riscritto in sequenza.",

                    ReplaceType.Hex =>
                        "Scrittura diretta/raw (editor hex, patcher binario, scrittura GENERIC_WRITE in-place).\n" +
                        "Pattern: Data extend → Data overwrite+extend → Data overwrite+extend+Close.\n" +
                        "Nessun 'Data truncation': il file non viene troncato, solo sovrascritto direttamente.",

                    _ =>
                        "Tipo di replace non determinabile dalla sequenza USN.\n" +
                        "L'evento non corrisponde a nessuno dei pattern Explorer, Copy, Type o HEX."
                };
            }
            return "Unknown";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    /// <summary>Background brush for Trust badge (solid color pill).</summary>
    public sealed class TrustToBadgeBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string trust = value?.ToString() ?? "";
            return trust switch
            {
                "Cheat"    => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#C0392B")),
                "Legit"    => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                "Unsigned" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E67E22")),
                "Spoofed"  => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#8E44AD")),
                _          => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4A5568"))
            };
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    /// <summary>Background brush for ReplaceType badge (solid color pill).</summary>
    public sealed class ReplaceTypeToBadgeBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is ReplaceType rt)
            {
                return rt switch
                {
                    ReplaceType.Explorer => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2980B9")),
                    ReplaceType.Copy     => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D4A017")),
                    ReplaceType.Type     => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                    ReplaceType.Hex      => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#C0392B")),
                    _                    => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4A5568"))
                };
            }
            return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4A5568"));
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
