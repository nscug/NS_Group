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
using System.Windows.Navigation;
using System.Collections.ObjectModel;
using System.IO;
using System.Data;

namespace NS_Client
{

    /// <summary>
    /// class people
    /// </summary>
    public struct people
    {
        public string ID { get; set;}
        public string Name{ get; set; }
        public string Phone{ get; set; }
        public string Else{ get; set; }
    }
    
    /// <summary>
    /// HomeWindow.xaml 的交互逻辑
    /// </summary>
    public partial class HomeWindow : Window
    {
        int h_socket;
        List<people> aList = new List<people>();
        string UserID;

        public HomeWindow(string user,int socket)
        {
            InitializeComponent();
            UserID = user;
            h_socket=socket;
            dataBinding();
        }

        /// <summary>
        /// read data from file?
        /// </summary>
        /// <returns></returns>
        List<people> Readin()
        { 
            List<people> temp = new List<people>();
            StreamReader sr= new StreamReader(@".\data.txt");
            if (sr == null) MessageBox.Show("文件读取异常");
            string nextLine = sr.ReadLine();
            int num = 1;
            people ps1 = new people();//单行数据
            while (nextLine != null)
            {
                if (num % 4 == 1)
                {
                    ps1.ID = nextLine;
                }
                else if(num % 4 == 2)
                {
                    ps1.Name = nextLine;
                }
                else if (num % 4 == 3)
                {
                    ps1.Phone = nextLine;
                }
                else if (num % 4 == 0)
                {
                    ps1.Else = nextLine;
                    temp.Add(ps1);
                }
                nextLine = sr.ReadLine();
                num++;
            }
            return temp;
        }

        /// <summary>
        /// binding data
        /// </summary>
        public void dataBinding()
        {
            if(aList!=null)
                aList = Readin();
            dataGrid.ItemsSource = aList;
            dataGrid.AutoGenerateColumns = false;//禁止自动添加列
            dataGrid.CanUserAddRows = false;//禁止自动添加行
        }

        /// <summary>
        /// Search
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Button_Click(object sender, RoutedEventArgs e)
        {
            //搜索
            string word = textBox.Text;
            HomeWindow hh = new HomeWindow(UserID, h_socket);
            hh.aList = compare(word);
            hh.dataGrid.ItemsSource = hh.aList;
            hh.dataGrid.AutoGenerateColumns = false;//禁止自动添加列
            hh.dataGrid.CanUserAddRows = false;//禁止自动添加行 compare(word);
            hh.Show();
        }

        /// <summary>
        /// compare word
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private List<people> compare(string word)
        {
            List<people> temp = new List<people>(); 
            foreach(people p in aList)
            {
                if (p.Name.Contains(word))
                    temp.Add(p);
            }
            return temp;
        }


        /// <summary>
        /// click get
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            //获取
            List<string> temp = new List<string>();
            temp=getInfo(aList[dataGrid.SelectedIndex].ID);
            pop_up pu = new pop_up(temp, UserID);
            pu.Show();
            /*List<people> tt = new List<people>();
            people t = new people();
            t.Phone = temp[0];
            t.Name = aList[dataGrid.SelectedIndex].Name;
            t.Else = aList[dataGrid.SelectedIndex].Else;
            tt.Add(t);
            dataGrid.ItemsSource = tt;*/
        }

        /// <summary>
        /// get aiming information
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        private List<string> getInfo(string ID)
        {
            ///接入接口
            DLLimport.Search(ID, h_socket);
            List<string> temp = new List<string>();
            StreamReader sr = new StreamReader(@".\phoneNum.txt");
            if (sr == null) MessageBox.Show("文件读取异常");
            string nextLine = sr.ReadLine();
            sr.Close();
            temp.Add(nextLine);
            return temp;
        }
    }
}

  
  
