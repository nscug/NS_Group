using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NS_Client
{
    class Log
    {
        /// <summary>
        /// write log
        /// </summary>
        /// <param name="choose"></param>
        public void WriteLog(int choose,string user)
        {
            using (System.IO.StreamWriter file = new System.IO.StreamWriter(".\\Log.txt", true))
            {
                if (file == null)
                    System.Console.Write("open fail");
                string line = "";
                switch (choose)
                {
                    case 1:
                        line = DateTime.Now.ToLocalTime().ToString() + ' ' + user + " Login Sucess";
                        break;
                    case 2:
                        line = DateTime.Now.ToLocalTime().ToString() + ' ' + user + " Login Fail";
                        break;

                }
                file.WriteLine(line);// 直接追加文件末尾，换行 
                file.Close();
            }
        }
    }
}
