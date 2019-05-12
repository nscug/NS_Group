using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace NS_Client
{
    /// <summary>
    /// pop_up.xaml 的交互逻辑
    /// </summary>
    public partial class pop_up : Window
    {
        public pop_up(List<string> L,string user)
        {
            InitializeComponent();
            textBlock_M.Text = L[0];
        }
    }
}
