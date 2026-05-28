using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using SSForensic.Models;

namespace SSForensic.Views
{
    public class FlagToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string flag = value as string ?? string.Empty;
            return flag switch
            {
                "REPLACE_DURING_JAVA" => new SolidColorBrush(Color.FromArgb(80, 229, 57, 53)),
                "ORIGINAL_CHEAT"      => new SolidColorBrush(Color.FromArgb(80, 30, 136, 229)),
                "ORIGINAL_LEGIT"      => new SolidColorBrush(Color.FromArgb(80, 67, 160, 71)),
                "ORIGINAL_UNSIGNED"   => new SolidColorBrush(Color.FromArgb(80, 251, 140, 0)),
                "EXT_SPOOFED"         => new SolidColorBrush(Color.FromArgb(80, 142, 36, 170)),
                _                     => Brushes.Transparent
            };
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }

    public class TrustToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is FileTrust t)
                return t switch
                {
                    FileTrust.Cheat      => new SolidColorBrush(Color.FromArgb(180, 30, 136, 229)),
                    FileTrust.Legit      => new SolidColorBrush(Color.FromArgb(180, 67, 160, 71)),
                    FileTrust.Unsigned   => new SolidColorBrush(Color.FromArgb(180, 251, 140, 0)),
                    FileTrust.ExtSpoofed => new SolidColorBrush(Color.FromArgb(180, 142, 36, 170)),
                    _                    => new SolidColorBrush(Color.FromArgb(100, 120, 120, 120))
                };
            return Brushes.Transparent;
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }

    public class BoolToVisConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b) return b ? Visibility.Visible : Visibility.Collapsed;
            if (value == null) return Visibility.Collapsed;
            return Visibility.Visible;
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => value is Visibility v && v == Visibility.Visible;
    }

    public class InvertBooleanConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
            => value is bool b ? !b : true;
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => value is bool b ? !b : false;
    }

    /// <summary>
    /// Before analysis (HasRun=false) the scrim is very light so clouds show through.
    /// After analysis (HasRun=true) it darkens for readability.
    /// </summary>
    public class HasRunToScrimOpacityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
            => (value is bool b && b) ? 1.0 : 0.25;
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}