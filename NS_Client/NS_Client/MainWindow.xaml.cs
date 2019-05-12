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
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Runtime.InteropServices;

namespace NS_Client
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        string user;
        int socket;
        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// login return true or false
        /// </summary>
        /// <returns></returns>
        public int Login()
        {
             string a = textBox.Text+'\0';
             string b = passwordBox1.Password+'\0';
          //  string a = "1\0";
          //  string b = "123456\0";
            // 初始化
            int result =DLLimport.Authentication(a,b);
           // int result = DLLimport.test("dd");
           
            ///调用接口
            return result;
        }

        private void Button_Login_Click(object sender, RoutedEventArgs e)
        {
            socket = Login();
            if ( socket > 0)
            {
                HomeWindow hm = new HomeWindow(textBox.Text, socket);
                this.Close();
                user = textBox.Text;
                new Log().WriteLog(1,user);
                hm.Show();
            }
            else if(socket== 0)
            {
                MessageBox.Show("账号或密码错误");
                new Log().WriteLog(2,user);
            }
            else if (socket == -1)
            {
                MessageBox.Show("服务器连接失败");
                new Log().WriteLog(2, user);
            }
        }
    }
}
