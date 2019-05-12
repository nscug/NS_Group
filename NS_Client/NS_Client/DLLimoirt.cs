using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;


namespace NS_Client
{
    class DLLimport
    {
        [DllImport(@"testdl.dll", CallingConvention = CallingConvention.Cdecl)]
        //下面是导入的dll的name
        public static extern int Authentication(string ID, string password);

        [DllImport(@"testdl.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int Search(string ID,int socket);

        [DllImport(@"testdl.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int test(string a);
    }
}
